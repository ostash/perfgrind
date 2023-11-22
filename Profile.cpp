#include "Profile.h"

#include "AddressResolver.h"

#include <algorithm>
#include <vector>
#include <tr1/unordered_set>
#include <climits>
#include <linux/perf_event.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#ifndef NDEBUG
#include <iostream>
#endif

static const std::string unknownFile("???");

namespace pe {

/// Data about mmap event
struct mmap_event
{
  __u32 pid;
  __u32 tid;
  __u64 address;
  __u64 length;
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

typedef std::tr1::unordered_set<std::string> StringTable;

SymbolData::SymbolData()
: sourceFile_(&unknownFile)
, sourceLine_(0)
{}

EntryData::EntryData(Count count)
: count_(count)
, sourceFile_(&unknownFile)
, sourceLine_(0)
{}

EntryData& MemoryObjectData::appendEntry(Address address, Count count)
{
  EntryData*& entryData = entries_[address];
  if (!entryData)
    entryData = new EntryData(count);
  else
    entryData->count_ += count;

  return *entryData;
}

void MemoryObjectData::appendBranch(Address from, Address to)
{
  appendEntry(from, 0).branches_[to]++;
}

void MemoryObjectData::resolveEntries(const AddressResolver& resolver, Address loadBase, StringTable* sourceFiles)
{
  // Set up correct base address
  baseAddress_ = resolver.baseAddress();
  // Take mmap page offset into consideration
  loadBase -= pageOffset_;
  // Perform resolving
  EntryStorage::iterator entryIt = entries_.begin();
  while (entryIt != entries_.end())
  {
    Range symbolRange;
    SymbolData* symbolData = new SymbolData();

    if (resolver.resolve(entryIt->first, loadBase, symbolRange, symbolData->name_))
    {
      if (sourceFiles)
      {
        const std::pair<const char*, size_t>& pos = resolver.getSourcePosition(symbolRange.start, loadBase);
        if (pos.first)
        {
          symbolData->sourceFile_ = &(*sourceFiles->insert(pos.first).first);
          symbolData->sourceLine_ = pos.second;
        }
      }
      symbols_.insert(Symbol(symbolRange, symbolData));
    }
    else
    {
      delete symbolData;
      delete entryIt->second;
      entries_.erase(entryIt++);
      continue;
    }

    do
    {
      if (sourceFiles)
      {
        const std::pair<const char*, size_t>& pos = resolver.getSourcePosition(entryIt->first, loadBase);
        if (pos.first)
        {
          entryIt->second->sourceFile_ = &(*sourceFiles->insert(pos.first).first);
          entryIt->second->sourceLine_ = pos.second;
        }
      }
      ++entryIt;
    }
    while (entryIt != entries_.end() && entryIt->first < symbolRange.end);
  }
}

void MemoryObjectData::fixupBranches(const MemoryObjectStorage& objects)
{
  // Fixup branches
  // Call "to" address should point to first address of called function,
  // this will allow group them as well
  EntryStorage::iterator entryIt = entries_.begin();
  while (entryIt != entries_.end())
  {
    EntryData& entryData = *(entryIt->second);
    if (entryData.branches().size() == 0)
    {
      ++entryIt;
      continue;
    }

    // Must exist, we drop unresolved entries earlier
    SymbolStorage::const_iterator selfSymIt = symbols_.find(Range(entryIt->first));

    EntryData fixedEntry(entryData.count());
    for (BranchStorage::const_iterator branchIt = entryData.branches().begin(); branchIt != entryData.branches().end();
         ++branchIt)
    {
      const Address& branchAddress = branchIt->first.address;
      const MemoryObjectData* callObjectData = objects.at(Range(branchAddress));
      SymbolStorage::const_iterator callSymbolIt = callObjectData->symbols_.find(Range(branchAddress));
      if (callSymbolIt != callObjectData->symbols().end())
      {
        if (callObjectData != this || callSymbolIt != selfSymIt)
          fixedEntry.branches_[&(*callSymbolIt)] += branchIt->second;
      }
    }

    if (fixedEntry.branches().size() != 0 || entryData.count() != 0)
    {
      entryData.count_ = fixedEntry.count_;
      std::swap(entryData.branches_, fixedEntry.branches_);
      ++entryIt;
    }
    else
    {
      delete entryIt->second;
      entries_.erase(entryIt++);
    }
  }
}

MemoryObjectData::MemoryObjectData(const char* fileName, Size pageOffset)
: baseAddress_(0)
, pageOffset_(pageOffset)
, fileName_(fileName)
{}

MemoryObjectData::~MemoryObjectData()
{
  for (EntryStorage::iterator entryIt = entries_.begin(); entryIt != entries_.end(); ++entryIt)
    delete entryIt->second;
}

// ProfilePrivate methods
class ProfilePrivate
{
  friend class Profile;
  ProfilePrivate()
    : mmapEventCount_(0)
    , goodSamplesCount_(0)
    , badSamplesCount_(0)
  {}
  ~ProfilePrivate();

  void processMmapEvent(const pe::mmap_event &event);
  void processSampleEvent(const pe::sample_event &event, Profile::Mode mode);

  void cleanupMemoryObjects();
  void resolveAndFixup(Profile::DetailLevel details);

  MemoryObjectStorage memoryObjects_;
  StringTable sourceFiles_;

  size_t mmapEventCount_;
  size_t goodSamplesCount_;
  size_t badSamplesCount_;
};

ProfilePrivate::~ProfilePrivate()
{
  for (MemoryObjectStorage::iterator objIt = memoryObjects_.begin(); objIt != memoryObjects_.end(); ++objIt)
    delete objIt->second;
}

void ProfilePrivate::processMmapEvent(const pe::mmap_event &event)
{
#ifndef NDEBUG
  std::pair<MemoryObjectStorage::const_iterator, bool> insRes =
#endif
  memoryObjects_.insert(MemoryObject(Range(event.address, event.address + event.length),
                                    new MemoryObjectData(event.fileName, event.pageOffset)));
#ifndef NDEBUG
  if (!insRes.second)
  {
    std::cerr << "Memory object was not inserted! " << event.address << " " << event.length << " "
              << event.fileName << '\n';
    std::cerr << "Already have another object: " << (insRes.first->first.start) << ' '
              << (insRes.first->first.end) << ' ' << insRes.first->second->fileName() << '\n';
    for (MemoryObjectStorage::const_iterator it = memoryObjects_.begin(); it != memoryObjects_.end(); ++it)
      std::cerr << it->first.start << ' ' << it->first.end << ' ' << it->second->fileName() << '\n';
    std::cerr << std::endl;
  }
#endif
  mmapEventCount_++;
}

void ProfilePrivate::processSampleEvent(const pe::sample_event &event, Profile::Mode mode)
{
  if (event.callchain[0] != PERF_CONTEXT_USER || event.callchainSize < 2 || event.callchainSize > PERF_MAX_STACK_DEPTH)
  {
    badSamplesCount_++;
    return;
  }

  MemoryObjectStorage::iterator objIt = memoryObjects_.find(Range(event.ip));
  if (objIt == memoryObjects_.end())
  {
    badSamplesCount_++;
    return;
  }

  objIt->second->appendEntry(event.ip, 1);
  goodSamplesCount_++;

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
    if (skipFrame || callFrom == callTo)
      continue;

    objIt = memoryObjects_.find(Range(callFrom));
    if (objIt == memoryObjects_.end())
      continue;

    objIt->second->appendBranch(callFrom, callTo);

    callTo = callFrom;
  }
}

void ProfilePrivate::cleanupMemoryObjects()
{
  // Drop memory objects that don't have any entries
  MemoryObjectStorage::iterator objIt = memoryObjects_.begin();
  while (objIt != memoryObjects_.end())
  {
    if (objIt->second->entries().size() == 0)
    {
      delete objIt->second;
      // With C++11 we can just do:
      // objIt = d->memoryObjects.erase(objIt);
      memoryObjects_.erase(objIt++);
    }
    else
      ++objIt;
  }
}

void ProfilePrivate::resolveAndFixup(Profile::DetailLevel details)
{
  for (MemoryObjectStorage::iterator objIt = memoryObjects_.begin(); objIt != memoryObjects_.end(); ++objIt)
  {
    AddressResolver r(details, objIt->second->fileName_.c_str(), objIt->first.end - objIt->first.start);
    objIt->second->resolveEntries(r, objIt->first.start, details == Profile::Sources ? &sourceFiles_ : 0);
  }
  for (MemoryObjectStorage::iterator objIt = memoryObjects_.begin(); objIt != memoryObjects_.end(); ++objIt)
    objIt->second->fixupBranches(memoryObjects_);
}

// Profile methods

Profile::Profile() : d(new ProfilePrivate)
{}

Profile::~Profile() { delete d; }

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

  d->cleanupMemoryObjects();
}

size_t Profile::mmapEventCount() const { return d->mmapEventCount_; }

size_t Profile::goodSamplesCount() const { return d->goodSamplesCount_; }

size_t Profile::badSamplesCount() const { return d->badSamplesCount_; }

void Profile::resolveAndFixup(DetailLevel details) { d->resolveAndFixup(details); }

const MemoryObjectStorage& Profile::memoryObjects() const { return d->memoryObjects_; }
