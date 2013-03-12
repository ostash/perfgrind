#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <vector>
#include <tr1/unordered_set>

#include <cxxabi.h>

#include <cerrno>
#include <climits>
#include <cstdlib>

#include <elfutils/libdwfl.h>

#include <linux/perf_event.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

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
  typedef std::set<Symbol> SymbolStorage;
  SymbolStorage allSymbols;
  SymbolStorage usedSymbols;
  std::tr1::unordered_set<std::string> sourceFiles;
  bool operator<(const MemoryObject& other) const
  {
    return start < other.start;
  }
  void attachSymbols();
  void loadSymbolsFromElfSection(Elf* elf, unsigned sectionType);
  void detachSymbols();
  const Symbol *resolveSymbol(__u64 addr);
  const Symbol* findSymbol(__u64 addr) const;
  SourcePosition getSourcePosition(__u64 addr);

  Dwfl* dwfl;
  Dwfl_Module* dwMod;
  __u64 adjust;
  GElf_Addr bias;
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
      std::pair<SymbolStorage::iterator, bool> symIns = allSymbols.insert(symbol);
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
  adjust = 0;
  bias = 0;
  dwfl = dwfl_begin(&callbacks);
  if (dwfl)
  {
    // First try main file
    dwMod = dwfl_report_offline(dwfl, "", fileName.c_str(), -1);
    if (dwMod)
    {
      Elf* elf = dwfl_module_getelf(dwMod, &bias);
      GElf_Ehdr elfHeader;
      gelf_getehdr(elf, &elfHeader);
      if (elfHeader.e_type == ET_DYN)
        adjust = start;
      loadSymbolsFromElfSection(elf, SHT_DYNSYM);
      loadSymbolsFromElfSection(elf, SHT_SYMTAB);

      // It could happen that we have debug info in separate file
      std::stringstream ss;
      ss << "/usr/lib/debug" << fileName << ".debug";
      std::string debugFile = ss.str();
      Dwfl_Module* debugMod = dwfl_report_offline(dwfl, "", debugFile.c_str(), -1);
      if (debugMod)
      {
        // Clean all
        dwfl_report_end(dwfl, 0, 0);
        // Load debug file
        dwMod = dwfl_report_offline(dwfl, "", debugFile.c_str(), -1);
        elf = dwfl_module_getelf(dwMod, &bias);

        loadSymbolsFromElfSection(elf, SHT_DYNSYM);
        loadSymbolsFromElfSection(elf, SHT_SYMTAB);
      }
    }
    else
      detachSymbols();
  }
  // Create fake symbols to cover gaps
  std::vector<Symbol> fakeSymbols;
  __u64 prevEnd = start - adjust;
  for (SymbolStorage::iterator symIt = allSymbols.begin(); symIt != allSymbols.end(); ++symIt)
  {
    if (symIt->start - prevEnd >= 4)
      fakeSymbols.push_back(Symbol(prevEnd, symIt->start, constructSymbolName(prevEnd)));

    // Expand asm label to next symbol
    if (symIt->start == symIt->end)
    {
      Symbol& symbol = const_cast<Symbol&>(*symIt);
      SymbolStorage::iterator nextSymIt = symIt;
      ++nextSymIt;
      if (nextSymIt == allSymbols.end())
        symbol.end = end - adjust;
      else
        symbol.end = nextSymIt->start;
      // add object base name
      std::stringstream ss;
      ss << symbol.name << '@' << baseName;
      symbol.name = ss.str();
    }
    prevEnd = symIt->end;
  }
  if (end - adjust - prevEnd >= 4)
    fakeSymbols.push_back(Symbol(prevEnd, end - adjust, constructSymbolName(prevEnd)));

  allSymbols.insert(fakeSymbols.begin(), fakeSymbols.end());
}

void MemoryObject::detachSymbols()
{
  if (!dwfl)
    return;
  dwfl_report_end(dwfl, 0, 0);
  dwfl_end(dwfl);
  dwMod = 0;
  dwfl = 0;
  allSymbols.clear();
}

const Symbol* MemoryObject::resolveSymbol(__u64 addr)
{
  // We must have it!
  SymbolStorage::iterator allSymbolsIt = allSymbols.upper_bound(Symbol(addr - adjust));
  --allSymbolsIt;

  SymbolStorage::iterator symIt = usedSymbols.insert(*allSymbolsIt).first;
  allSymbols.erase(allSymbolsIt);

  const_cast<Symbol&>(*symIt).startSrcPos = getSourcePosition(symIt->start);

  return  &(*symIt);
}

const Symbol* MemoryObject::findSymbol(__u64 addr) const
{
  // We must have it!
  SymbolStorage::iterator symIt = usedSymbols.upper_bound(Symbol(addr - adjust));
  --symIt;
  return &(*symIt);
}

SourcePosition MemoryObject::getSourcePosition(__u64 addr)
{
  SourcePosition pos;
  if (dwfl)
  {
    Dwfl_Line* line = dwfl_getsrc(dwfl, addr - adjust + bias);
    if (line)
    {
      int linep;
      const char* srcFile = dwfl_lineinfo(line, 0, &linep, 0, 0, 0);
      if (srcFile)
      {
        pos.srcFile = &(*sourceFiles.insert(srcFile).first);
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
  const Symbol* curSymbol = 0;
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
    if (!curSymbol || insAddr - curObj->adjust >= curSymbol->end)
      curSymbol = curObj->resolveSymbol(insAddr);

    instr.symbol = curSymbol;
    instr.exclusiveCost.sourcePos = curObj->getSourcePosition(insAddr);
  }
  if (curObj)
    curObj->detachSymbols();

  // Fixup calls
  // Call "to" addresses should point to first address of called function,
  // this will allow group them as well
  for (InstrInfoStorage::iterator insIt = instructions_.begin(); insIt != instructions_.end(); ++insIt)
  {
    InstrInfo& instr = const_cast<InstrInfo&>(*insIt);
    InstrInfo::CallCostStorage fixuped;
    for (InstrInfo::CallCostStorage::iterator cIt = instr.callCosts.begin(); cIt != instr.callCosts.end(); ++cIt)
    {
      const MemoryObject& callObject = getMemoryObjectByAddr(cIt->addr);
      const Symbol* callSymbol = callObject.findSymbol(cIt->addr);
      Cost &fixupedCallCost = const_cast<Cost&>(*fixuped.insert(Cost(callSymbol->start + callObject.adjust)).first);

      fixupedCallCost.count += cIt->count;
      fixupedCallCost.sourcePos = callSymbol->startSrcPos;
    }
    instr.callCosts.swap(fixuped);
  }
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
  os << "positions: line\n";
  os << "events: Cycles\n\n";

  MemoryObject* curObj = 0;
  const Symbol* curSymbol = 0;
  const std::string unknownFile = "???";
  const std::string* curFile = 0;
  for (InstrInfoStorage::iterator insIt = instructions_.begin(); insIt != instructions_.end(); ++insIt)
  {
    const InstrInfo& instr = *insIt;
    __u64 insAddr = instr.exclusiveCost.addr;
    if (!curObj || insAddr >= curObj->end)
    {
      curSymbol = 0;
      curFile = 0;
      curObj = &getMemoryObjectByAddr(insAddr);
      os << "ob=" << curObj->fileName << '\n';
    }
    if (!curFile || (curFile == &unknownFile && instr.exclusiveCost.sourcePos.srcFile)
        || (curFile != &unknownFile && curFile != instr.exclusiveCost.sourcePos.srcFile))
    {
      curFile = instr.exclusiveCost.sourcePos.srcFile ?: &unknownFile;
      os << "fl=" << *curFile << '\n';
    }
    if (!curSymbol || insAddr - curObj->adjust >= curSymbol->end)
    {
      curSymbol = instr.symbol;
      os << "fn=" << curSymbol->name << '\n';
    }

    if (instr.exclusiveCost.count != 0)
      os << instr.exclusiveCost.sourcePos.srcLine << ' ' << instr.exclusiveCost.count << '\n';

    for (InstrInfo::CallCostStorage::const_iterator cIt = instr.callCosts.begin(); cIt != instr.callCosts.end();
         ++cIt)
    {
      const MemoryObject& callObject = getMemoryObjectByAddr(cIt->addr);
      os << "cob=" << callObject.fileName << '\n';
      const Symbol* callSymbol = callObject.findSymbol(cIt->addr);
      os << "cfi=";
      if (callSymbol->startSrcPos.srcFile)
        os << *callSymbol->startSrcPos.srcFile;
      else
        os << unknownFile;
      os << '\n';
      os << "cfn=" << callSymbol->name << '\n';
      os << "calls=1 " << callSymbol->startSrcPos.srcLine <<  '\n';
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
