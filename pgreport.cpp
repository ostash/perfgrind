#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <map>
#include <set>
#include <vector>

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

struct MemoryObject
{
  MemoryObject(const perf_event& event)
    : start(event.mmap_event.addr)
    , end(event.mmap_event.addr + event.mmap_event.len)
    , offset(event.mmap_event.pgoff)
    , fileName(event.mmap_event.filename)
  {}
  MemoryObject() : fileName("[unknown]") {}
  __u64 start;
  __u64 end;
  __u64 offset;
  std::string fileName;
  bool operator<(const MemoryObject& other) const
  {
    return start < other.start;
  }
};

struct Sample
{
  Sample(__u64 _addr) : addr(_addr), count(1) {}
  __u64 addr;
  __u64 count;
  bool operator<(const Sample& other) const
  {
    return addr < other.addr;
  }
};

class Profile
{
public:
  void addMemoryObject(const perf_event& event);
  void addSample(const perf_event& event);

  void process();

  void dump(std::ostream& os) const;
private:
  typedef std::set<MemoryObject> MemoryMap;
  typedef std::set<Sample> SamplesStorage;

  void dumpSamplesRange(std::ostream &os, SamplesStorage::const_iterator start, SamplesStorage::const_iterator finish) const;

  MemoryMap memoryMap_;
  SamplesStorage samples_;
};

void Profile::addMemoryObject(const perf_event &event)
{
  memoryMap_.insert(MemoryObject(event));
}

void Profile::addSample(const perf_event &event)
{
  std::pair<SamplesStorage::iterator, bool> sampleInsertion =samples_.insert(Sample(event.sample_event.ip));
  if (!sampleInsertion.second)
    ((Sample&)*sampleInsertion.first).count++;
}

void Profile::process()
{
}

void Profile::dump(std::ostream &os) const
{
  if (!samples_.size())
    return;

  os << "events: Cycles\n";

  unsigned unknownObjectId = 1;

  SamplesStorage::const_iterator prevIt = samples_.begin();

  for (MemoryMap::const_iterator objIt = memoryMap_.begin(); objIt != memoryMap_.end(); ++objIt)
  {
    const MemoryObject& object = *objIt;
    SamplesStorage::const_iterator lowIt = samples_.lower_bound(object.start);
    if (prevIt != lowIt)
    {
      os << "ob=[unknown_" << unknownObjectId << "]\n";
      dumpSamplesRange(os, prevIt, lowIt);
      os << '\n';
      unknownObjectId++;
    }

    os << "# " << std::hex << object.start << '-' << object.end << ' ' << object.offset << ' ' << object.fileName << '\n';

    SamplesStorage::const_iterator upperIt = samples_.upper_bound(object.end);
    if (lowIt != upperIt)
    {
      os << "ob=" << object.fileName << '\n';
      dumpSamplesRange(os, lowIt, upperIt);
      os << '\n';
    }

    prevIt = upperIt;
  }

  if (prevIt != samples_.end())
  {
    os << "ob=[unknown_" << unknownObjectId << "]\n";
    dumpSamplesRange(os, prevIt, samples_.end());
    os << '\n';
    unknownObjectId++;
  }

}

void Profile::dumpSamplesRange(std::ostream& os, SamplesStorage::const_iterator start,
                               SamplesStorage::const_iterator finish) const
{
  for (; start != finish; start++)
  {
    __u64 adrInObj = start->addr/* - object.start + object.offset*/;
    os << "0x" << std::hex << adrInObj << ' ' << std::dec << start->count << '\n';
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
  __u64 eventCount = 0;

  while (readEvent(input, event))
  {
    eventCount++;
    processEvent(profile, event);
  }

  std::cout << "# " << eventCount << " events processed\n";

  profile.process();
  profile.dump(std::cout);

  return 0;
}
