#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <set>
#include <vector>
#include <tr1/unordered_set>
#include <tr1/unordered_map>

#include <ext/functional>

#include <cxxabi.h>

#include <cerrno>
#include <climits>
#include <cstdlib>

#include <elfutils/libdwfl.h>

#include <linux/perf_event.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

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

}

bool readEvent(std::istream& is, pe::perf_event& event)
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
  SourcePosition() : srcFile(0), srcLine(0) {}
  const std::string* srcFile;
  unsigned srcLine;
};

struct Symbol
{
  Symbol(__u64 _start, __u64 _end, const std::string& _name)
    : start(_start)
    , end(_end)
  {
    char* demangledName = __cxxabiv1::__cxa_demangle(_name.c_str(), 0, 0, 0);
    if (demangledName)
      name = demangledName;
    else
      name = _name.c_str();
  }
  explicit Symbol(__u64 addr) : start(addr) {}
  __u64 start;
  __u64 end;
  char binding;
  std::string name;
  SourcePosition startSrcPos;

  bool operator<(const Symbol& other) const
  {
    return start < other.start;
  }
};

class MemoryObject
{
public:
  /// Constructs memory object performance event
  MemoryObject(const pe::mmap_event& event)
    : start_(event.address)
    , end_(event.address + event.length)
    , fileName_(event.fileName)
    , baseName_(fileName_.substr(fileName_.rfind('/') + 1))
  {}

  /// Returns start address at which object was placed in program image
  __u64 start() const { return start_; }
  /// Returns end address at which object was placed in program image
  __u64 end() const { return end_; }
  /// Returns full path to object file
  const std::string& fileName() const { return fileName_; }

  /// Maps given address from global space to object space
  __u64 mapTo(__u64 address) const { return address - start_ + adjust_; }
  /// Unmaps given address from object space to global space
  __u64 unmapFrom(__u64 address) const { return address + start_ - adjust_; }

  void attachSymbols();
  void detachSymbols();
  const Symbol& resolveSymbol(__u64 address);
  SourcePosition getSourcePosition(__u64 address);

  /** \brief Returns symbol that covers given address
   *  \param address Address in object's space */
  const Symbol& findSymbol(__u64 address) const;

  /// Compare start addresses of two memory objects
  bool operator<(const MemoryObject& other) const
  {
    return start_ < other.start_;
  }
private:
  const __u64 start_;
  const __u64 end_;
  const std::string fileName_;
  const std::string baseName_;

  typedef std::set<Symbol> SymbolStorage;
  SymbolStorage allSymbols_;
  SymbolStorage usedSymbols_;

  std::tr1::unordered_set<std::string> sourceFiles_;
  Dwfl* dwfl_;
  Dwfl_Module* dwMod_;
  __u64 adjust_;
  GElf_Addr dwBias_;

  void loadSymbolsFromElfSection(Elf* elf, unsigned sectionType);
};

static Dwfl_Callbacks callbacks = {
  dwfl_build_id_find_elf,
  dwfl_standard_find_debuginfo,
  dwfl_offline_section_address,
  0
};

std::string constructSymbolName(__u64 addr)
{
  std::stringstream ss;
  ss << "func_" << std::hex << addr;
  return ss.str();
}

void MemoryObject::loadSymbolsFromElfSection(Elf *elf, unsigned sectionType)
{
  Elf_Scn* scn = 0;
  while ((scn = elf_nextscn(elf, scn)) != 0)
  {
    GElf_Shdr sectHeader;
    gelf_getshdr (scn, &sectHeader);

    if (sectHeader.sh_type != sectionType)
      continue;

    Elf_Data* symData = elf_getdata(scn, 0);

    size_t symCount = sectHeader.sh_size / (sectHeader.sh_entsize ? sectHeader.sh_entsize : 1);

    for (size_t symIdx = 0; symIdx < symCount; symIdx++)
    {
      GElf_Sym elfSym;
      gelf_getsym(symData, symIdx, &elfSym);

      if (ELF32_ST_TYPE(elfSym.st_info) != STT_FUNC || elfSym.st_value == 0)
        continue;

      Symbol symbol(elfSym.st_value, elfSym.st_value + elfSym.st_size,
                    elf_strptr(elf, sectHeader.sh_link, elfSym.st_name));

      symbol.binding = ELF32_ST_BIND(elfSym.st_info);
      std::pair<SymbolStorage::iterator, bool> symIns = allSymbols_.insert(symbol);
      if (!symIns.second)
      {
        Symbol& oldSym = const_cast<Symbol&>(*symIns.first);
        // Sized functions better that asm labels
        if (oldSym.end == oldSym.start && elfSym.st_size != 0)
        {
          oldSym.name = symbol.name;
          oldSym.binding = symbol.binding;
          oldSym.end = symbol.end;
        }
        else
        // G > W > L
        if (symbol.binding == STB_GLOBAL || (symbol.binding == STB_WEAK && oldSym.binding == STB_LOCAL))
        {
          oldSym.name = symbol.name;
          oldSym.binding = symbol.binding;
        }
      }
    }
  }
}

void MemoryObject::attachSymbols()
{
  adjust_ = 0;
  dwBias_ = 0;
  dwfl_ = dwfl_begin(&callbacks);
  if (dwfl_)
  {
    // First try main file
    dwMod_ = dwfl_report_offline(dwfl_, "", fileName_.c_str(), -1);
    if (dwMod_)
    {
      Elf* elf = dwfl_module_getelf(dwMod_, &dwBias_);
      GElf_Ehdr elfHeader;
      gelf_getehdr(elf, &elfHeader);

      for (int i = 0; i < elfHeader.e_phnum; i++)
      {
        GElf_Phdr phdr;
        gelf_getphdr(elf, i, &phdr);
        if (phdr.p_type == PT_LOAD)
        {
          adjust_ = phdr.p_vaddr;
          break;
        }
      }

      loadSymbolsFromElfSection(elf, SHT_DYNSYM);
      loadSymbolsFromElfSection(elf, SHT_SYMTAB);

      // It could happen that we have debug info in separate file
      std::stringstream ss;
      ss << "/usr/lib/debug" << fileName_ << ".debug";
      std::string debugFile = ss.str();
      Dwfl_Module* debugMod = dwfl_report_offline(dwfl_, "", debugFile.c_str(), -1);
      if (debugMod)
      {
        // Clean all
        dwfl_report_end(dwfl_, 0, 0);
        // Load debug file
        dwMod_ = dwfl_report_offline(dwfl_, "", debugFile.c_str(), -1);
        elf = dwfl_module_getelf(dwMod_, &dwBias_);

        loadSymbolsFromElfSection(elf, SHT_DYNSYM);
        loadSymbolsFromElfSection(elf, SHT_SYMTAB);
      }
    }
    else
      detachSymbols();
  }
  // Create fake symbols to cover gaps
  std::vector<Symbol> fakeSymbols;
  __u64 prevEnd = adjust_;
  for (SymbolStorage::iterator symIt = allSymbols_.begin(); symIt != allSymbols_.end(); ++symIt)
  {
    if (symIt->start - prevEnd >= 4)
      fakeSymbols.push_back(Symbol(prevEnd, symIt->start, constructSymbolName(prevEnd)));

    // Expand asm label to next symbol
    if (symIt->start == symIt->end)
    {
      Symbol& symbol = const_cast<Symbol&>(*symIt);
      SymbolStorage::iterator nextSymIt = symIt;
      ++nextSymIt;
      if (nextSymIt == allSymbols_.end())
        symbol.end = end_ - start_ + adjust_;
      else
        symbol.end = nextSymIt->start;
      // add object base name
      std::stringstream ss;
      ss << symbol.name << '@' << baseName_;
      symbol.name = ss.str();
    }
    prevEnd = symIt->end;
  }
  if (end_ - start_ + adjust_ - prevEnd >= 4)
    fakeSymbols.push_back(Symbol(prevEnd, end_ - start_ + adjust_, constructSymbolName(prevEnd)));

  allSymbols_.insert(fakeSymbols.begin(), fakeSymbols.end());
}

void MemoryObject::detachSymbols()
{
  if (!dwfl_)
    return;
  dwfl_report_end(dwfl_, 0, 0);
  dwfl_end(dwfl_);
  dwMod_ = 0;
  dwfl_ = 0;
  allSymbols_.clear();
}

const Symbol& MemoryObject::resolveSymbol(__u64 address)
{
  // We must have it!
  SymbolStorage::iterator allSymbolsIt = allSymbols_.upper_bound(Symbol(address));
  --allSymbolsIt;

  SymbolStorage::iterator symIt = usedSymbols_.insert(*allSymbolsIt).first;
  allSymbols_.erase(allSymbolsIt);

  const_cast<Symbol&>(*symIt).startSrcPos = getSourcePosition(symIt->start);

  return  *symIt;
}

const Symbol &MemoryObject::findSymbol(__u64 address) const
{
  // We must have it!
  SymbolStorage::iterator symIt = usedSymbols_.upper_bound(Symbol(address));
  --symIt;
  return *symIt;
}

SourcePosition MemoryObject::getSourcePosition(__u64 address)
{
  SourcePosition pos;
  if (dwfl_)
  {
    Dwfl_Line* line = dwfl_getsrc(dwfl_, address + dwBias_);
    if (line)
    {
      int linep;
      const char* srcFile = dwfl_lineinfo(line, 0, &linep, 0, 0, 0);
      if (srcFile)
      {
        pos.srcFile = &(*sourceFiles_.insert(srcFile).first);
        pos.srcLine = linep;
      }
    }
  }

  return pos;
}

struct Cost
{
  explicit Cost(__u64 _addr) : addr(_addr), count(0) {}
  __u64 addr;
  __u64 count;
  SourcePosition sourcePos;
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
  const Symbol* symbol;
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
  enum Mode { Flat = 0, Callgraph = 1 };
  Profile(Mode mode = Flat)
    : mode_(mode)
    , badSamplesCount_(0)
    , goodSamplesCount_(0)
  {}

  void addMemoryObject(const pe::mmap_event &event);
  void addSample(const pe::sample_event &event);

  void process();

  void dump(std::ostream& os) const;
private:
  Mode mode_;

  typedef std::map<__u64, MemoryObject> MemoryMap;
  typedef std::tr1::unordered_map<__u64, InstrInfo> InstrInfoStorage;
  typedef std::vector<__u64> InstrAddrStorage;

  bool isMappedAddress(__u64 isMappedAddress) const;
  MemoryObject &findMemoryObject(__u64 address);
  const MemoryObject& findMemoryObject(__u64 address) const;
  InstrInfo& getOrCreateInstrInfo(__u64 addr);

  MemoryMap memoryMap_;
  InstrInfoStorage instructions_;
  InstrAddrStorage instrAddrs_;
  size_t badSamplesCount_;
  size_t goodSamplesCount_;
};

void Profile::addMemoryObject(const pe::mmap_event &event)
{
  memoryMap_.insert(MemoryMap::value_type(event.address, MemoryObject(event)));
}

void Profile::addSample(const pe::sample_event &event)
{
  if (!isMappedAddress(event.ip) || event.callchainSize < 2 ||
      event.callchain[0] != PERF_CONTEXT_USER)
  {
    badSamplesCount_++;
    return;
  }

  {
    InstrInfo& instr = getOrCreateInstrInfo(event.ip);
    instr.exclusiveCost.count++;
    goodSamplesCount_++;
  }

  if (mode_ == Flat)
    return;

  bool skipFrame = false;
  __u64 callTo = event.ip;

  for (__u64 i = 2; i < event.callchainSize; ++i)
  {
    __u64 callFrom = event.callchain[i];
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
}

void Profile::process()
{
  instrAddrs_.resize(instructions_.size());
  std::transform(instructions_.begin(), instructions_.end(), instrAddrs_.begin(),
                 __gnu_cxx::select1st<InstrInfoStorage::value_type>());
  std::sort(instrAddrs_.begin(), instrAddrs_.end());

  MemoryObject* curObj = 0;
  const Symbol* curSymbol = 0;
  for (size_t i = 0; i < instrAddrs_.size(); i++)
  {
    __u64 globalAddr = instrAddrs_[i];
    InstrInfo& instr = instructions_.find(globalAddr)->second;

    if (!curObj || globalAddr >= curObj->end())
    {
      if (curObj)
        curObj->detachSymbols();
      curSymbol = 0;
      curObj = &findMemoryObject(globalAddr);
      curObj->attachSymbols();
    }
    __u64 mappedAddress = curObj->mapTo(globalAddr);
    if (!curSymbol || mappedAddress >= curSymbol->end)
      curSymbol = &curObj->resolveSymbol(mappedAddress);

    instr.symbol = curSymbol;
    instr.exclusiveCost.sourcePos = curObj->getSourcePosition(mappedAddress);
  }
  if (curObj)
    curObj->detachSymbols();

  // Fixup calls
  // Call "to" addresses should point to first address of called function,
  // this will allow group them as well
  for (InstrInfoStorage::iterator insIt = instructions_.begin(); insIt != instructions_.end(); ++insIt)
  {
    InstrInfo& instr = insIt->second;
    InstrInfo::CallCostStorage fixuped;
    for (InstrInfo::CallCostStorage::iterator cIt = instr.callCosts.begin(); cIt != instr.callCosts.end(); ++cIt)
    {
      const MemoryObject& callObject = findMemoryObject(cIt->addr);
      const Symbol& callSymbol = callObject.findSymbol(callObject.mapTo(cIt->addr));
      Cost &fixupedCallCost = const_cast<Cost&>(*fixuped.insert(Cost(callObject.unmapFrom(callSymbol.start))).first);
      fixupedCallCost.count += cIt->count;
      fixupedCallCost.sourcePos = callSymbol.startSrcPos;
    }
    instr.callCosts.swap(fixuped);
  }
}

bool Profile::isMappedAddress(__u64 address) const
{
  MemoryMap::const_iterator objIt = memoryMap_.upper_bound(address);

  if (objIt != memoryMap_.begin())
  {
    --objIt;
    return address >= objIt->second.start() && address < objIt->second.end();
  }

  return false;
}

MemoryObject& Profile::findMemoryObject(__u64 address)
{
  return (--(memoryMap_.upper_bound(address)))->second;
}

const MemoryObject& Profile::findMemoryObject(__u64 address) const
{
  return (--(memoryMap_.upper_bound(address)))->second;
}

InstrInfo& Profile::getOrCreateInstrInfo(__u64 addr)
{
  std::pair<InstrInfoStorage::iterator, bool> instrIns =
      instructions_.insert(InstrInfoStorage::value_type(addr, InstrInfo(addr)));
  return instrIns.first->second;
}

void Profile::dump(std::ostream &os) const
{
  os << "positions: line\n";
  os << "events: Cycles\n\n";

  const MemoryObject* curObj = 0;
  const Symbol* curSymbol = 0;
  const std::string unknownFile = "???";
  const std::string* curFile = 0;
  for (size_t i = 0; i < instrAddrs_.size(); i++)
  {
    __u64 globalAddr = instrAddrs_[i];
    const InstrInfo& instr = instructions_.find(globalAddr)->second;

    if (!curObj || globalAddr >= curObj->end())
    {
      curSymbol = 0;
      curFile = 0;
      curObj = &findMemoryObject(globalAddr);
      os << "ob=" << curObj->fileName() << '\n';
    }
    if (!curFile || (curFile == &unknownFile && instr.exclusiveCost.sourcePos.srcFile)
        || (curFile != &unknownFile && curFile != instr.exclusiveCost.sourcePos.srcFile))
    {
      curFile = instr.exclusiveCost.sourcePos.srcFile ?: &unknownFile;
      os << "fl=" << *curFile << '\n';
    }
    if (!curSymbol || curObj->mapTo(globalAddr) >= curSymbol->end)
    {
      curSymbol = instr.symbol;
      os << "fn=" << curSymbol->name << '\n';
    }

    if (instr.exclusiveCost.count != 0)
      os << instr.exclusiveCost.sourcePos.srcLine << ' ' << instr.exclusiveCost.count << '\n';

    for (InstrInfo::CallCostStorage::const_iterator cIt = instr.callCosts.begin(); cIt != instr.callCosts.end();
         ++cIt)
    {
      const MemoryObject& callObject = findMemoryObject(cIt->addr);
      os << "cob=" << callObject.fileName() << '\n';
      const Symbol& callSymbol = callObject.findSymbol(callObject.mapTo(cIt->addr));
      os << "cfi=";
      if (callSymbol.startSrcPos.srcFile)
        os << *callSymbol.startSrcPos.srcFile;
      else
        os << unknownFile;
      os << '\n';
      os << "cfn=" << callSymbol.name << '\n';
      os << "calls=1 " << callSymbol.startSrcPos.srcLine <<  '\n';
      os << instr.exclusiveCost.sourcePos.srcLine << ' ' << cIt->count << '\n';
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

void processEvent(Profile& profile, const pe::perf_event& event)
{
  switch (event.header.type)
  {
  case PERF_RECORD_MMAP:
    profile.addMemoryObject(event.mmap);
    break;
  case PERF_RECORD_SAMPLE:
    profile.addSample(event.sample);
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

  Profile profile(Profile::Callgraph);
  pe::perf_event event;

  while (readEvent(input, event))
    processEvent(profile, event);

  profile.process();
  profile.dump(std::cout);

  return 0;
}
