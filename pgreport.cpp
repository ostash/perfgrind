#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <tr1/unordered_set>

#include <cerrno>
#include <climits>
#include <cstdlib>

#include <linux/perf_event.h>

struct perf_event
{
  struct perf_event_header header;
  union {
    struct {
      __u32 pid, tid;
      __u64 addr;
      __u64 len;
      __u64 pgoff;
      char filename[PATH_MAX];
    } mmap_event;
    struct {
      __u64   ip;          /* if PERF_SAMPLE_IP      */
      __u64   nr;        /* if PERF_SAMPLE_CALLCHAIN */
      __u64   ips[PERF_MAX_STACK_DEPTH];   /* if PERF_SAMPLE_CALLCHAIN */
    } sample_event;
  };
};

bool readEvent(std::istream& is, perf_event& event)
{
  is.read((char*)&event, sizeof(perf_event_header));
  if (is.eof() || is.fail())
    return false;
  is.read(((char*)&event) + sizeof(perf_event_header), event.header.size - sizeof(perf_event_header));
  if (is.eof() || is.fail())
    return false;

  return true;
}

struct SourcePosition
{
  std::string* srcFile;
  unsigned srcLine;
};

struct Symbol
{
  __u64 start;
  __u64 end;
  std::string name;
  SourcePosition srcPos;
};

struct MemoryObject
{
  MemoryObject(const perf_event& event)
    : start(event.mmap_event.addr)
    , end(event.mmap_event.addr + event.mmap_event.len)
    , offset(event.mmap_event.pgoff)
    , fileName(event.mmap_event.filename)
  {
    baseName = fileName.substr(fileName.rfind('/') + 1);
  }
  explicit MemoryObject(__u64 addr) : start(addr) {}

  __u64 start;
  __u64 end;
  __u64 offset;
  std::string fileName;
  std::string baseName;
  std::tr1::unordered_set<Symbol> symbols;
  bool operator<(const MemoryObject& other) const
  {
    return start < other.start;
  }
  void attachSymbols();
  void detachSymbols();
  Symbol* getOrCreateSymbol(__u64 addr);
  SourcePosition getSourcePosition(__u64 addr);
};

void MemoryObject::attachSymbols()
{

}

void MemoryObject::detachSymbols()
{

}

Symbol* MemoryObject::getOrCreateSymbol(__u64 addr)
{
  static Symbol sym = { };
  return &sym;
}

SourcePosition MemoryObject::getSourcePosition(__u64 addr)
{
  SourcePosition pos = {0, 0};
  return pos;
}

struct Cost
{
  explicit Cost(__u64 _addr) : addr(_addr), count(0) {}
  __u64 addr;
  __u64 count;
  bool operator<(const Cost& other) const
  {
    return addr < other.addr;
  }
};

struct InstrInfo
{
  explicit InstrInfo(__u64 addr) : exclusiveCost(addr), symbol(0) {}
  Cost exclusiveCost;
  typedef std::set<Cost> CallCostStorage;
  CallCostStorage callCosts;
  Symbol* symbol;
  SourcePosition sourcePos;
  bool operator<(const InstrInfo& other) const
  {
    return exclusiveCost < other.exclusiveCost;
  }
  Cost& getOrCreateCallCost(__u64 addr);
};

Cost& InstrInfo::getOrCreateCallCost(__u64 addr)
{
  std::pair<CallCostStorage::iterator, bool> callIns = callCosts.insert(Cost(addr));
  return const_cast<Cost&>(*callIns.first);
}

class Profile
{
public:
  Profile() : badSamplesCount_(0), goodSamplesCount_(0) {}
  void addMemoryObject(const perf_event& event);
  void addSample(const perf_event& event);

  void process();

  void dump(std::ostream& os) const;
private:
  typedef std::set<MemoryObject> MemoryMap;
  typedef std::set<InstrInfo> InstrInfoStorage;

  bool isMappedAddress(__u64 addr) const;
  MemoryObject& getMemoryObjectByAddr(__u64 addr) const;
  InstrInfo& getOrCreateInstrInfo(__u64 addr);
  void dumpSamplesRange(std::ostream &os, InstrInfoStorage::const_iterator start,
                        InstrInfoStorage::const_iterator finish) const;

  MemoryMap memoryMap_;
  InstrInfoStorage instructions_;
  size_t badSamplesCount_;
  size_t goodSamplesCount_;
};

void Profile::addMemoryObject(const perf_event &event)
{
  memoryMap_.insert(MemoryObject(event));
}

void Profile::addSample(const perf_event &event)
{
  if (!isMappedAddress(event.sample_event.ip) || event.sample_event.nr < 2 ||
      event.sample_event.ips[0] != PERF_CONTEXT_USER)
  {
    badSamplesCount_++;
    return;
  }

  {
    InstrInfo& instr = getOrCreateInstrInfo(event.sample_event.ip);
    instr.exclusiveCost.count++;
  }

  bool skipFrame = false;
  __u64 callTo = event.sample_event.ip;

  for (__u64 frameIdx = 2; frameIdx < event.sample_event.nr; ++frameIdx)
  {
    __u64 callFrom = event.sample_event.ips[frameIdx];
    if (callFrom > PERF_CONTEXT_MAX)
    {
      // Context switch, and we want only user level
      skipFrame = (callFrom != PERF_CONTEXT_USER);
      continue;
    }
    if (skipFrame || !isMappedAddress(callFrom) || callFrom == callTo)
      continue;

    InstrInfo& instr = getOrCreateInstrInfo(callFrom);
    Cost& callCost = instr.getOrCreateCallCost(callTo);
    callCost.count++;

    callTo = callFrom;
  }

  goodSamplesCount_++;
}

void Profile::process()
{
  MemoryObject* curObj = 0;
  Symbol* curSymbol = 0;
  for (InstrInfoStorage::iterator insIt = instructions_.begin(); insIt != instructions_.end(); ++insIt)
  {
    InstrInfo& instr = const_cast<InstrInfo&>(*insIt);
    __u64 insAddr = instr.exclusiveCost.addr;
    if (!curObj || insAddr >= curObj->end)
    {
      if (curObj)
        curObj->detachSymbols();
      curSymbol = 0;
      curObj = &getMemoryObjectByAddr(insAddr);
      curObj->attachSymbols();
    }
    if (!curSymbol || insAddr >= curSymbol->end)
      curSymbol = curObj->getOrCreateSymbol(insAddr);

    instr.symbol = curSymbol;
    instr.sourcePos = curObj->getSourcePosition(insAddr);
    // call will be resolved during dumping
  }
  if (curObj)
    curObj->detachSymbols();
}

bool Profile::isMappedAddress(__u64 addr) const
{
  MemoryMap::const_iterator objIt = memoryMap_.upper_bound(MemoryObject(addr));

  if (objIt != memoryMap_.begin())
  {
    --objIt;
   return addr >= objIt->start && addr < objIt->end;
  }

  return false;
}

MemoryObject& Profile::getMemoryObjectByAddr(__u64 addr) const
{
  return const_cast<MemoryObject&>(*(--(memoryMap_.upper_bound(MemoryObject(addr)))));
}

InstrInfo& Profile::getOrCreateInstrInfo(__u64 addr)
{
  std::pair<InstrInfoStorage::iterator, bool> instrIns = instructions_.insert(InstrInfo(addr));
  return const_cast<InstrInfo&>(*instrIns.first);
}

void Profile::dump(std::ostream &os) const
{
  os << "positions: instr\n";
  os << "events: Cycles\n\n";

  for (MemoryMap::const_iterator objIt = memoryMap_.begin(); objIt != memoryMap_.end(); ++objIt)
  {
    const MemoryObject& object = *objIt;
    os << "# " << std::hex << object.start << '-' << object.end << ' ' << object.offset << std::dec
       << ' ' << object.fileName << '\n';

    InstrInfoStorage::const_iterator lowIt = instructions_.lower_bound(InstrInfo(object.start));
    InstrInfoStorage::const_iterator upperIt = instructions_.upper_bound(InstrInfo(object.end));
    if (lowIt != upperIt)
    {
      os << "ob=" << object.fileName << '\n';
      os << "fn=whole_" << object.baseName << '\n';
      dumpSamplesRange(os, lowIt, upperIt);
      os << '\n';
    }
  }

  os << "\n# memory objects: " << memoryMap_.size()
     << "\n# sampled addresses: " << instructions_.size()
     << "\n\n# good sample events: " << goodSamplesCount_
     << "\n# bad sample events: " << badSamplesCount_
     << "\n# total sample events: " << badSamplesCount_ + goodSamplesCount_
     << "\n# total events: " << badSamplesCount_ + goodSamplesCount_ + memoryMap_.size()
     << '\n';
}

void Profile::dumpSamplesRange(std::ostream& os, InstrInfoStorage::const_iterator start,
                               InstrInfoStorage::const_iterator finish) const
{
  for (; start != finish; start++)
  {
    if (start->exclusiveCost.count == 0)
      os << "# ";
    os << "0x" << std::hex << start->exclusiveCost.addr << ' ' << std::dec << start->exclusiveCost.count << '\n';
    for (InstrInfo::CallCostStorage::const_iterator cIt = start->callCosts.begin(); cIt != start->callCosts.end();
         ++cIt)
    {
      const MemoryObject& object = getMemoryObjectByAddr(cIt->addr);
      os << "cob=" << object.fileName << '\n';
      os << "cfn=whole_" << object.baseName << '\n';
      os << "calls=1 " << std::hex << "0x" << cIt->addr << std::dec << '\n';
      os << "0x" << std::hex << start->exclusiveCost.addr << ' ' << std::dec << cIt->count << '\n';
    }
  }
}

void processEvent(Profile& profile, const perf_event& event)
{
  switch (event.header.type)
  {
  case PERF_RECORD_MMAP:
    profile.addMemoryObject(event);
    break;
  case PERF_RECORD_SAMPLE:
    profile.addSample(event);
  }
}

int main(int argc, char** argv)
{
  if (argc < 2)
  {
    std::cout << "Usage: " << program_invocation_short_name << " filename.pgdata\n";
    exit(EXIT_SUCCESS);
  }

  std::fstream input(argv[1], std::ios_base::in);
  if (!input)
  {
    std::cerr << "Error reading input file " << argv[1] << '\n';
    exit(EXIT_FAILURE);
  }

  Profile profile;
  perf_event event;

  while (readEvent(input, event))
    processEvent(profile, event);

  profile.process();
  profile.dump(std::cout);

  return 0;
}
