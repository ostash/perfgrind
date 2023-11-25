#include "Profile.h"

#include "AddressResolver.h"

#include <algorithm>
#include <climits>
#include <vector>

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

std::ostream& operator<<(std::ostream& os, const Range& range)
{
  const auto f = os.flags();
  os << "0x" << std::hex << range.start() << " 0x" << range.end();
  os.flags(f);
  return os;
}

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
  auto& entryData =
    entries_.emplace(std::piecewise_construct, std::forward_as_tuple(address), std::forward_as_tuple(0)).first->second;

  entryData.count_ += count;

  return entryData;
}

void MemoryObjectData::appendBranch(Address from, Address to)
{
  appendEntry(from, 0).branches_[to]++;
}

void MemoryObjectData::resolveEntries(const AddressResolver& resolver, const Address startAddress,
                                      StringTable* sourceFiles)
{
  // Save whether we use absolute addresses for this memory object
  usesAbsoluteAddresses_ = resolver.usesAbsoluteAddresses();

  // Perform resolving
  EntryStorage::iterator entryIt = entries_.begin();
  while (entryIt != entries_.end())
  {
    Range symbolRange;
    SymbolData* symbolData = new SymbolData();
    const auto& resolveResult = resolver.resolve(mapToElf(startAddress, entryIt->first));
    if (!resolveResult.second.isEmpty())
    {
      symbolRange = Range(mapFromElf(startAddress, resolveResult.second.start()),
                          mapFromElf(startAddress, resolveResult.second.end()));
      symbolData->name_ = !resolveResult.first.empty() ?
                            resolveResult.first :
                            AddressResolver::constructSymbolNameFromAddress(symbolRange.start());
      if (sourceFiles)
      {
        const std::pair<const char*, size_t>& pos = resolver.getSourcePosition(resolveResult.second.start());
        if (pos.first)
        {
          symbolData->sourceFile_ = &(*sourceFiles->insert(pos.first).first);
          symbolData->sourceLine_ = pos.second;
        }
      }
      symbols_.emplace(symbolRange, symbolData);
    }
    else
    {
      delete symbolData;
      entryIt = entries_.erase(entryIt);
      continue;
    }

    do
    {
      if (sourceFiles)
      {
        const std::pair<const char*, size_t>& pos = resolver.getSourcePosition(mapToElf(startAddress, entryIt->first));
        if (pos.first)
        {
          entryIt->second.sourceFile_ = &(*sourceFiles->insert(pos.first).first);
          entryIt->second.sourceLine_ = pos.second;
        }
      }
      ++entryIt;
    }
    while (entryIt != entries_.end() && entryIt->first < symbolRange.end());
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
    EntryData& entryData = entryIt->second;
    if (entryData.branches().size() == 0)
    {
      ++entryIt;
      continue;
    }

    // Must exist, we drop unresolved entries earlier
    SymbolStorage::const_iterator selfSymIt = symbols_.find(Range(entryIt->first));

    EntryData fixedEntry(entryData.count());
    for (const auto& branch: entryData.branches())
    {
      const Address& branchAddress = branch.first.address;
      const MemoryObjectData& callObjectData = objects.at(Range(branchAddress));
      SymbolStorage::const_iterator callSymbolIt = callObjectData.symbols_.find(Range(branchAddress));
      if (callSymbolIt != callObjectData.symbols().end())
      {
        if (&callObjectData != this || callSymbolIt != selfSymIt)
          fixedEntry.branches_[&(*callSymbolIt)] += branch.second;
      }
    }

    if (fixedEntry.branches().size() != 0 || entryData.count() != 0)
    {
      entryData.count_ = fixedEntry.count_;
      std::swap(entryData.branches_, fixedEntry.branches_);
      ++entryIt;
    }
    else
      entryIt = entries_.erase(entryIt);
  }
}

MemoryObjectData::MemoryObjectData(const char* fileName, Size pageOffset)
: pageOffset_(pageOffset)
, fileName_(fileName)
{}

void Profile::processMmapEvent(const pe::mmap_event& event)
{
#ifndef NDEBUG
  auto insRes =
#endif
    memoryObjects_.emplace(std::piecewise_construct, std::forward_as_tuple(event.address, event.address + event.length),
                           std::forward_as_tuple(event.fileName, event.pageOffset));
#ifndef NDEBUG
  if (!insRes.second)
  {
    std::cerr << "Memory object was not inserted! " << event.address << " " << event.length << " "
              << event.fileName << '\n';
    std::cerr << "Already have another object: " << insRes.first->first << ' ' << insRes.first->second.fileName()
              << '\n';
    for (const auto& memoryObject: memoryObjects_)
      std::cerr << memoryObject.first << ' ' << memoryObject.second.fileName() << '\n';
    std::cerr << std::endl;
  }
#endif
  mmapEventCount_++;
}

void Profile::processSampleEvent(const pe::sample_event& event, const ProfileMode mode)
{
  if (event.callchain[0] != PERF_CONTEXT_USER || event.callchainSize < 2)
  {
    // Callchain which starts not in the user space

    nonUserSamples_++;
    return;
  }

  auto memoryObjectIt = memoryObjects_.find(Range(event.ip));
  if (memoryObjectIt == memoryObjects_.end())
  {
    // Instruction pointer does not point any memory mapped object
    unmappedSamples_++;
    return;
  }

  memoryObjectIt->second.appendEntry(event.ip, 1);
  goodSamplesCount_++;

  if (mode != ProfileMode::CallGraph)
    return;

  bool skipFrame = false;
  Address callTo = event.ip;

  // NOTE: On recent kernels callchain depth can be controlled via sysctl kernel.perf_event_max_stack and
  // kernel.perf_event_max_contexts_per_stack and they can be deeper then PERF_MAX_STACK_DEPTH.
  for (__u64 i = 2; i < event.callchainSize && i < PERF_MAX_STACK_DEPTH; ++i)
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

    memoryObjectIt = memoryObjects_.find(Range(callFrom));
    if (memoryObjectIt == memoryObjects_.end())
      // We rely on frame-pointer based stack unwinding, which is not "reliable". If application was not built with
      // -fno-omit-frame-pointer the callchain will contain invalid entries so we just skip addresses not belonging to
      // any memory object.
      continue;

    memoryObjectIt->second.appendBranch(callFrom, callTo);

    callTo = callFrom;
  }
}

void Profile::cleanupMemoryObjects()
{
  // Drop memory objects that don't have any entries
  auto memoryObjectIt = memoryObjects_.begin();
  while (memoryObjectIt != memoryObjects_.end())
  {
    if (memoryObjectIt->second.entries().empty())
    {
      memoryObjectIt = memoryObjects_.erase(memoryObjectIt);
    }
    else
      ++memoryObjectIt;
  }
}

void Profile::resolveAndFixup(const ProfileDetails details)
{
  for (auto& memoryObject: memoryObjects_)
  {
    const AddressResolver r(details, memoryObject.second.fileName_.c_str(), memoryObject.first.length());
    memoryObject.second.resolveEntries(r, memoryObject.first.start(),
                                       details == ProfileDetails::Sources ? &sourceFiles_ : 0);
  }

  for (auto& memoryObject: memoryObjects_)
    memoryObject.second.fixupBranches(memoryObjects_);
}

void Profile::load(std::istream& is, const ProfileMode mode)
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
      processMmapEvent(event.mmap);
      break;
    case PERF_RECORD_SAMPLE:
      processSampleEvent(event.sample, mode);
    }
  }

  cleanupMemoryObjects();
}
