#include "AddressResolver.h"

#include <algorithm>
#include <map>
#include <sstream>
#include <cstring>

#include <cxxabi.h>

#include <fcntl.h>

#include <elfutils/libdwfl.h>

#ifndef NDEBUG
#include <iostream>
#endif

enum Section {
  SymTab = 0,
  DynSym,
  DebugInfo,
  DebugLink,
  PrelinkUndo,
  PLT,
  RelPLT,
  SectionCount
};

class ElfHolder
{
public:
  explicit ElfHolder(const char* fileName);
  ~ElfHolder();

  void open(const char* fileName);
  void close();

  Elf* get() { return elf_; }
  Elf_Scn* getSection(Section section) { return sections_[section]; }
  uint64_t getBaseAddress() const { return baseAddress_; }
private:
  ElfHolder(const ElfHolder&);
  ElfHolder& operator=(const ElfHolder&);

  void loadInfo();

  uint64_t baseAddress_;
  Elf* elf_;
  Elf_Scn* sections_[SectionCount];
  int fd_;
};

ElfHolder::ElfHolder(const char *fileName)
  : baseAddress_(0)
{
  memset(sections_, 0, sizeof(sections_));
  fd_ = ::open(fileName, O_RDONLY);
  elf_ = elf_begin(fd_, ELF_C_READ, 0);
  loadInfo();
}

ElfHolder::~ElfHolder()
{
  elf_end(elf_);
  ::close(fd_);
}

void ElfHolder::open(const char *fileName)
{
  elf_end(elf_);
  if (fd_)
    ::close(fd_);

  baseAddress_ = 0;
  memset(sections_, 0, sizeof(sections_));

  fd_ = ::open(fileName, O_RDONLY);
  elf_ = elf_begin(fd_, ELF_C_READ, 0);
  loadInfo();
}

void ElfHolder::close()
{
  elf_end(elf_);
  ::close(fd_);
  elf_ = 0;
  fd_ = -1;
  baseAddress_ = 0;
  memset(sections_, 0, sizeof(sections_));
}

void ElfHolder::loadInfo()
{
  if (!elf_)
    return;

  // Detect base address
  size_t phCount;
  elf_getphdrnum(elf_, &phCount);
  for (size_t i = 0; i < phCount; i++)
  {
    GElf_Phdr phdr;
    gelf_getphdr(elf_, i, &phdr);
    if (phdr.p_type == PT_LOAD)
    {
      baseAddress_ = phdr.p_vaddr;
      break;
    }
  }

  // Find sections we are interested in
  GElf_Ehdr ehdr;
  gelf_getehdr(elf_, &ehdr);

  unsigned needToFind = SectionCount;
  size_t shCount;
  elf_getshdrnum(elf_, &shCount);
  for (size_t i = 0; i < shCount && needToFind > 0; i++)
  {
    Elf_Scn* scn = elf_getscn(elf_, i);
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);
    const char* sectionName;

    switch (shdr.sh_type)
    {
    case SHT_SYMTAB:
      sections_[SymTab] = scn;
      needToFind--;
      break;
    case SHT_DYNSYM:
      sections_[DynSym] = scn;
      needToFind--;
      break;
    case SHT_PROGBITS:
      sectionName = elf_strptr(elf_, ehdr.e_shstrndx, shdr.sh_name);
      if (strcmp(sectionName, ".debug_info") == 0)
      {
        sections_[DebugInfo] = scn;
        needToFind--;
      }
      else if (strcmp(sectionName, ".gnu_debuglink") == 0)
      {
        sections_[DebugLink] = scn;
        needToFind--;
      }
      else if (strcmp(sectionName, ".gnu.prelink_undo") == 0)
      {
        sections_[PrelinkUndo] = scn;
        needToFind--;
      }
      else if (strcmp(sectionName, ".plt") == 0)
      {
        sections_[PLT] = scn;
        needToFind--;
      }
      break;
    case SHT_REL:
    case SHT_RELA:
      sectionName = elf_strptr(elf_, ehdr.e_shstrndx, shdr.sh_name);
      if (strcmp(sectionName, ".rel.plt") == 0 || strcmp(sectionName, "rela.plt"))
      {
        sections_[RelPLT] = scn;
        needToFind--;
      }
      break;
    }
  }
}

struct ARSymbolData
{
  enum { MiscPLT = 255 };
  explicit ARSymbolData(const GElf_Sym& elfSymbol)
    : size(elfSymbol.st_size)
    , misc(GELF_ST_BIND(elfSymbol.st_info))
  {}
  explicit ARSymbolData(uint64_t _size)
    : size(_size)
  {}
  ARSymbolData() {}
  uint64_t size;
  std::string name;
  unsigned char misc;
};

typedef std::map<Range, ARSymbolData> ARSymbolStorage;
typedef ARSymbolStorage::value_type ARSymbol;

struct AddressResolverPrivate
{
  AddressResolverPrivate()
    : baseAddress(0)
    , origBaseAddress(0)
    , pltEndAddress(0)
    , dwfl(0)
    , dwMod(0)
    , dwBias(0)
  {}

  void loadPLTSymbols(Elf* elf, Elf_Scn* pltSection, Elf_Scn* relPltSection, Elf_Scn *dynsymSection);
  void loadSymbolsFromSection(Elf* elf, Elf_Scn* section);
  const char* getDebugLink(Elf_Scn* section);
  void setOriginalBaseAddress(Elf* elf, Elf_Scn* section);

  void constructFakeSymbols(Profile::DetailLevel details, uint64_t objectSize, const char* baseName);

  uint64_t baseAddress;
  uint64_t origBaseAddress;
  uint64_t pltEndAddress;

  Dwfl* dwfl;
  Dwfl_Module* dwMod;
  GElf_Addr dwBias;

  ARSymbolStorage symbols;
};

static Dwfl_Callbacks callbacks = {
  dwfl_build_id_find_elf,
  dwfl_standard_find_debuginfo,
  dwfl_offline_section_address,
  0
};

AddressResolver::AddressResolver(Profile::DetailLevel details, const char *fileName, uint64_t objectSize)
  : d(new AddressResolverPrivate)

{
  elf_version(EV_CURRENT);
  ElfHolder elfh(fileName);
  d->origBaseAddress = d->baseAddress = elfh.getBaseAddress();

  if (details != Profile::Objects && elfh.getSection(PLT) && elfh.getSection(RelPLT) && elfh.getSection(DynSym))
    d->loadPLTSymbols(elfh.get(), elfh.getSection(PLT), elfh.getSection(RelPLT), elfh.getSection(DynSym));

  // Don't load symbols if not requested
  bool symTabLoaded = (details == Profile::Objects);
  // Try to load .symtab from main file
  if (!symTabLoaded && elfh.getSection(SymTab))
  {
    d->loadSymbolsFromSection(elfh.get(), elfh.getSection(SymTab));
    symTabLoaded = true;
  }
  else if (!symTabLoaded && elfh.getSection(DynSym))
    // Try to load .dynsym from main file
    d->loadSymbolsFromSection(elfh.get(), elfh.getSection(DynSym));

  if (details != Profile::Objects && elfh.getSection(PrelinkUndo) && elfh.getSection(DebugLink))
    d->setOriginalBaseAddress(elfh.get(), elfh.getSection(PrelinkUndo));

  std::string debugModuleName = fileName;
  if (details != Profile::Objects && elfh.getSection(DebugLink))
  {
    // Get name
    debugModuleName = "/usr/lib/debug";
    debugModuleName.append(fileName);
    debugModuleName.append(".debug");
    /// @todo Use debug link

    if (!symTabLoaded)
    {
      elfh.close();
      elfh.open(debugModuleName.c_str());
      if (elfh.getSection(SymTab))
        d->loadSymbolsFromSection(elfh.get(), elfh.getSection(SymTab));
    }
  }

  elfh.close();

  d->constructFakeSymbols(details, objectSize, basename(fileName));

  if (details == Profile::Sources)
  {
    // Setup dwfl for sources positions fetching
    d->dwfl = dwfl_begin(&callbacks);
    d->dwMod = dwfl_report_offline(d->dwfl, "",debugModuleName.c_str(), -1);
    dwfl_module_getdwarf(d->dwMod, &d->dwBias);
  }
}

AddressResolver::~AddressResolver()
{
  if (d->dwfl)
    dwfl_report_end(d->dwfl, 0, 0);
  dwfl_end(d->dwfl);
  delete d;
}

Address AddressResolver::baseAddress() const
{
  return d->baseAddress;
}

static std::string constructSymbolName(uint64_t address)
{
  std::stringstream ss;
  ss << "func_" << std::hex << address;
  return ss.str();
}

bool AddressResolver::resolve(Address value, Address loadBase, Range& symbolRange, std::string& symbolName) const
{
  uint64_t adjust = loadBase - d->baseAddress;
  ARSymbolStorage::const_iterator arSymIt = d->symbols.find(Range(value - adjust));
  if (arSymIt == d->symbols.end())
  {
#ifndef NDEBUG
  std::cerr << "Can't resolve symbol for address " << std::hex << value - adjust
            << ", load base: " << loadBase << std::dec << '\n';
#endif

    return false;
  }

  symbolRange.start = arSymIt->first.start + adjust;
  symbolRange.end = arSymIt->first.end + adjust;

  const std::string& maybeSymbolName = arSymIt->second.name;
  if (maybeSymbolName.empty())
    symbolName = constructSymbolName(symbolRange.start);
  else
  {
    char* demangledName = __cxxabiv1::__cxa_demangle(maybeSymbolName.c_str(), 0, 0, 0);
    if (demangledName)
    {
      symbolName = demangledName;
      free(demangledName);
    }
    else
      symbolName = maybeSymbolName;

    if (arSymIt->second.misc == ARSymbolData::MiscPLT)
      symbolName.append("@plt");
  }

  return true;
}

std::pair<const char*, size_t> AddressResolver::getSourcePosition(Address value, Address loadBase) const
{
  if (d->dwfl)
  {
    Dwfl_Line* line = dwfl_getsrc(d->dwfl, value - loadBase + d->origBaseAddress + d->dwBias);
    if (line)
    {
      int linep = 0;
      const char* srcFile = dwfl_lineinfo(line, 0, &linep, 0, 0, 0);
        return std::make_pair(srcFile, linep);
    }
  }

  return std::make_pair(static_cast<const char*>(0), 0);
}

void AddressResolverPrivate::loadPLTSymbols(Elf* elf, Elf_Scn *pltSection, Elf_Scn *relPltSection, Elf_Scn *dynsymSection)
{
  GElf_Shdr header;

  gelf_getshdr(pltSection, &header);
  Address symStart = header.sh_addr;
  Count symSize = header.sh_entsize;

  gelf_getshdr(relPltSection, &header);
  bool isRela = header.sh_type == SHT_RELA;
  size_t relPltCount = header.sh_size / header.sh_entsize;

  gelf_getshdr(dynsymSection, &header);
  int strtabIdx = header.sh_link;

  Elf_Data* relPltData = elf_getdata(relPltSection, 0);
  Elf_Data* dynsymData = elf_getdata(dynsymSection, 0);

  for (size_t relPltIdx = 0; relPltIdx < relPltCount; relPltIdx++)
  {
    size_t symIdx;
    if (isRela)
    {
      GElf_Rela rela;
      gelf_getrela(relPltData, relPltIdx, &rela);
      symIdx = GELF_R_SYM(rela.r_info);
    }
    else
    {
      GElf_Rel rel;
      gelf_getrel(relPltData, relPltIdx, &rel);
      symIdx = GELF_R_SYM(rel.r_info);
    }

    GElf_Sym elfSymbol;
    gelf_getsym(dynsymData, symIdx, &elfSymbol);


    ARSymbolData& symbolData = symbols[Range(symStart, symStart + symSize)];
    symbolData.name = elf_strptr(elf, strtabIdx, elfSymbol.st_name);
    symbolData.misc = ARSymbolData::MiscPLT;

    symStart += symSize;
  }

  pltEndAddress = symStart;
}

void AddressResolverPrivate::loadSymbolsFromSection(Elf* elf, Elf_Scn *section)
{
  symbols.erase(symbols.lower_bound(Range(pltEndAddress)), symbols.end());

  GElf_Shdr sectionHeader;
  gelf_getshdr(section, &sectionHeader);

  Elf_Data* sectionData = elf_getdata(section, 0);
  size_t symbolCount = sectionHeader.sh_size / (sectionHeader.sh_entsize ? sectionHeader.sh_entsize : 1);

  for (size_t symIdx = 0; symIdx < symbolCount; symIdx++)
  {
    GElf_Sym elfSymbol;
    gelf_getsym(sectionData, symIdx, &elfSymbol);

    if (GELF_ST_TYPE(elfSymbol.st_info) != STT_FUNC || elfSymbol.st_shndx == SHN_UNDEF)
      continue;

    ARSymbolData symbolData(elfSymbol);
    uint64_t symStart = elfSymbol.st_value - origBaseAddress + baseAddress;
    uint64_t symEnd = symStart + (elfSymbol.st_size ?: 1);

    std::pair<ARSymbolStorage::iterator, bool> insResult =
        symbols.insert(ARSymbol(Range(symStart, symEnd), symbolData));
    if (insResult.second)
      insResult.first->second.name = elf_strptr(elf, sectionHeader.sh_link, elfSymbol.st_name);
    else
    {
      const ARSymbolData& oldSymbolData = insResult.first->second;
      // Sized functions better that asm labels and higer binding is also better
      if ((oldSymbolData.size == 0 && symbolData.size != 0) || (oldSymbolData.misc < symbolData.misc))
      {
        symbols.erase(insResult.first);
        symbolData.name = elf_strptr(elf, sectionHeader.sh_link, elfSymbol.st_name);
        symbols.insert(ARSymbol(Range(symStart, symEnd), symbolData));
      }
    }
  }
}

//const char* AddressResolver::getDebugLink(Elf_Scn* section)
//{
//  Elf_Data* sectionData = elf_rawdata(section, 0);
//  return (char*)sectionData->d_buf;
//}

void AddressResolverPrivate::setOriginalBaseAddress(Elf *elf, Elf_Scn* section)
{
  Elf_Data* sectionData = elf_rawdata(section, 0);
  // Allmost direct copy-paste from elfutils/libdwfl/dwfl_module_getdwarf.c
  union
  {
    Elf32_Ehdr e32;
    Elf64_Ehdr e64;
  } ehdr;

  Elf_Data destination;
  destination.d_buf = &ehdr;
  destination.d_size = sizeof(ehdr);
  destination.d_type = ELF_T_EHDR;
  destination.d_version = EV_CURRENT;

  Elf_Data source = *sectionData;
  source.d_size = gelf_fsize(elf, ELF_T_EHDR, 1, EV_CURRENT);
  source.d_type = ELF_T_EHDR;

  unsigned int encode = elf_getident(elf, NULL)[EI_DATA];

  gelf_xlatetom(elf, &destination, &source, encode);

  unsigned phnum;
  if (ehdr.e32.e_ident[EI_CLASS] == ELFCLASS32)
    phnum = ehdr.e32.e_phnum;
  else
    phnum = ehdr.e64.e_phnum;

  size_t phentsize = gelf_fsize(elf, ELF_T_PHDR, 1, EV_CURRENT);
  source.d_buf = (char*)source.d_buf + source.d_size;
  source.d_type = ELF_T_PHDR;
  source.d_size = phnum * phentsize;

  Elf64_Phdr phdr64[phnum];
  Elf32_Phdr* phdr32 = (Elf32_Phdr*)phdr64;
  destination.d_buf = &phdr64;
  destination.d_size = sizeof(phdr64);
  gelf_xlatetom(elf, &destination, &source, encode);
  if (ehdr.e32.e_ident[EI_CLASS] == ELFCLASS32)
  {
    for (unsigned i = 0; i < phnum; ++i)
      if (phdr32[i].p_type == PT_LOAD)
      {
        origBaseAddress = phdr32[i].p_vaddr;
        break;
      }
  }
  else
    for (unsigned i = 0; i < phnum; ++i)
      if (phdr64[i].p_type == PT_LOAD)
      {
        origBaseAddress = phdr64[i].p_vaddr;
        break;
      }
}

void AddressResolverPrivate::constructFakeSymbols(Profile::DetailLevel details, uint64_t objectSize,
                                                  const char* baseName)
{
  // Create fake symbols to cover gaps
  ARSymbolStorage newSymbols;
  uint64_t prevEnd = baseAddress;
  for (ARSymbolStorage::iterator symIt = symbols.begin(); symIt != symbols.end(); ++symIt)
  {
    const Range& symRange = symIt->first;
    if (symRange.start - prevEnd >= 4)
      newSymbols.insert(ARSymbol(Range(prevEnd, symRange.start), ARSymbolData(symRange.start - prevEnd)));

    // Expand asm label to next symbol
    if (symIt->second.size == 0)
    {
      ARSymbolStorage::iterator nextSymIt = symIt;
      ++nextSymIt;
      uint64_t newEnd;
      if (nextSymIt == symbols.end())
        newEnd = baseAddress + objectSize;
      else
        newEnd = nextSymIt->first.start;

      ARSymbolData newSymbolData(newEnd - symRange.start);
      newSymbolData.name = symIt->second.name.append(1, '@').append(baseName);

      newSymbols.insert(ARSymbol(Range(symRange.start, newEnd), newSymbolData));

      prevEnd = newEnd;
    }
    else
    {
      newSymbols.insert(*symIt);
      prevEnd = symRange.end;
    }
  }
  if (baseAddress + objectSize - prevEnd >= 4)
  {
    ARSymbolData newSymbolData(baseAddress + objectSize - prevEnd);
    if (details == Profile::Objects)
      (newSymbolData.name = "whole").append(1, '@').append(baseName);
    newSymbols.insert(ARSymbol(Range(prevEnd, baseAddress + objectSize), newSymbolData));
  }

  symbols.swap(newSymbols);
}
