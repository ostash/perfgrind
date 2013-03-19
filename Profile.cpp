#include "Profile.h"

#include <algorithm>
#include <vector>
#include <climits>
#include <linux/perf_event.h>

void EntryData::appendBranch(Address address, Count count)
{
  BranchStorage::iterator branchIt = branches_.find(address);
  if (branchIt == branches_.end())
    branches_.insert(Branch(address, count));
  else
    branchIt->second += count;
}

namespace pe {

/// Data about mmap event
struct mmap_event
{
  __u32 pid;
  __u32 tid;
  __u64 address;
  __u64 length;
  /// @todo Determine how to handle pgoff
  __u64 pageOffset;
  char fileName[PATH_MAX];
};

/// Data about sample event
/** We have enabled only PERF_SAMPLE_IP and PERF_SAMPLE_CALLCHAIN in \ref createPerfEvent in \ref pgcollect.c,
 *  so we define only this small subset of fields. */
struct sample_event
{
  __u64   ip;
  __u64   callchainSize;
  __u64   callchain[PERF_MAX_STACK_DEPTH];
};

struct perf_event
{
  struct perf_event_header header;
  union {
    mmap_event mmap;
    sample_event sample;
  };
};

std::istream& operator>>(std::istream& is, perf_event& event)
{
  is.read((char*)&event, sizeof(perf_event_header));
  is.read(((char*)&event) + sizeof(perf_event_header), event.header.size - sizeof(perf_event_header));
  return is;
}

}

class Index : public std::vector<Address>
{
public:
  Index() : lastValid_(0) {}
  void update();
private:
  size_t lastValid_;
};

void Index::update()
{
  if (lastValid_ == size())
    return;
  std::sort(begin() + lastValid_, end());
  std::inplace_merge(begin(), begin() + lastValid_, end());
  lastValid_ = size();
}

struct ProfilePrivate
{
  ProfilePrivate()
    : goodSamplesCount(0)
    , badSamplesCount(0)
  {}

  void processMmapEvent(const pe::mmap_event &event);

  void processSampleEvent(const pe::sample_event &event, Profile::Mode mode);
  EntryData &appendEntry(Address address, Count count);
  void appendBranch(Address from, Address to, Count count);

  bool isValidAdress(Address address) const;

  const Symbol& findSymbol(Address Address) const;

  MemoryObjectStorage memoryObjects;
#if ENABLE_MEMORY_INDEX
  mutable Index memoryObjectIndex;
#endif
  SymbolStorage symbols;
  Index symbolIndex;
  EntryStorage entries;

  size_t goodSamplesCount;
  size_t badSamplesCount;
};

void ProfilePrivate::processMmapEvent(const pe::mmap_event &event)
{
  memoryObjects.insert(MemoryObject(event.address, MemoryObjectData(event.length, event.fileName)));
#if ENABLE_MEMORY_INDEX
  memoryObjectIndex.push_back(event.address);
#endif
}

void ProfilePrivate::processSampleEvent(const pe::sample_event &event, Profile::Mode mode)
{
  if (event.callchain[0] != PERF_CONTEXT_USER ||
      !isValidAdress(event.ip) ||
      event.callchainSize < 2 || event.callchainSize > PERF_MAX_STACK_DEPTH)
  {
    badSamplesCount++;
    return;
  }

  appendEntry(event.ip, 1);
  goodSamplesCount++;

  if (mode != Profile::CallGraph)
    return;

  bool skipFrame = false;
  Address callTo = event.ip;

  for (__u64 i = 2; i < event.callchainSize; ++i)
  {
    Address callFrom = event.callchain[i];
    if (callFrom > PERF_CONTEXT_MAX)
    {
      // Context switch, and we want only user level
      skipFrame = (callFrom != PERF_CONTEXT_USER);
      continue;
    }
    if (skipFrame || callFrom == callTo || !isValidAdress(callFrom))
      continue;

    appendBranch(callFrom, callTo, 1);

    callTo = callFrom;
  }
}

EntryData& ProfilePrivate::appendEntry(Address address, Count count)
{
  EntryStorage::iterator entryIt = entries.find(address);
  if (entryIt == entries.end())
    entryIt = entries.insert(Entry(address, EntryData(count))).first;
  else
    entryIt->second.addCount(count);

  return entryIt->second;
}

void ProfilePrivate::appendBranch(Address from, Address to, Count count)
{
  appendEntry(from, 0).appendBranch(to, count);
}

bool ProfilePrivate::isValidAdress(Address address) const
{
#if ENABLE_MEMORY_INDEX
  memoryObjectIndex.update();
  Index::const_iterator idxIt = std::upper_bound(memoryObjectIndex.begin(), memoryObjectIndex.end(), address);

  if (idxIt != memoryObjectIndex.begin())
  {
    --idxIt;
    const MemoryObjectData& object = memoryObjects.find(*idxIt)->second;
    return address < *idxIt + object.size();
  }
  return false;
#else
  MemoryObjectStorage::const_iterator objIt = memoryObjects.upper_bound(address);

  if (objIt != memoryObjects.begin())
  {
    --objIt;
    return address >= objIt->first && address < objIt->first + objIt->second.size();
  }

  return false;
#endif
}

const Symbol& ProfilePrivate::findSymbol(Address address) const
{
  Index::const_iterator symbolIdxIt = std::upper_bound(symbolIndex.begin(), symbolIndex.end(), address);
  --symbolIdxIt;
  return *symbols.find(*symbolIdxIt);
}

Profile::Profile() : d(new ProfilePrivate)
{}

Profile::~Profile()
{
  delete d;
}

void Profile::load(std::istream &is, Mode mode)
{
  pe::perf_event event;
  while (!is.eof() && !is.fail())
  {
    is >> event;
    if (is.eof() || is.fail())
      break;
    switch (event.header.type)
    {
    case PERF_RECORD_MMAP:
      d->processMmapEvent(event.mmap);
      break;
    case PERF_RECORD_SAMPLE:
      d->processSampleEvent(event.sample, mode);
    }
  }
}

size_t Profile::goodSamplesCount() const
{
  return d->goodSamplesCount;
}

size_t Profile::badSamplesCount() const
{
  return d->badSamplesCount;
}

void Profile::fixupBranches()
{
  // Fixup branches
  // Call "to" address should point to first address of called function,
  // this will allow group them as well
  for (EntryStorage::iterator entryIt = d->entries.begin(); entryIt != d->entries.end(); ++entryIt)
  {
    EntryData& entryData = entryIt->second;
    if (entryData.branches().size() == 0)
      continue;

    EntryData fixedEntry(entryData.count());
    for (BranchStorage::const_iterator branchIt = entryData.branches().begin(); branchIt != entryData.branches().end();
         ++branchIt)
    {
      const Symbol& symbol = d->findSymbol(branchIt->first);
      fixedEntry.appendBranch(symbol.first, branchIt->second);
    }
    entryData.swap(fixedEntry);
  }
}

const MemoryObjectStorage& Profile::memoryObjects() const
{
  return d->memoryObjects;
}

const SymbolStorage& Profile::symbols() const
{
  return d->symbols;
}

SymbolStorage& Profile::symbols()
{
  return d->symbols;
}

const EntryStorage& Profile::entries() const
{
  return d->entries;
}
