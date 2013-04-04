#include "Profile.h"
#include "AddressResolver.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <numeric>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <getopt.h>

struct Params
{
  Params()
    : mode(Profile::CallGraph)
    , details(Profile::Sources)
    , dumpInstructions(false)
    , inputFile(0)
  {}
  Profile::Mode mode;
  Profile::DetailLevel details;
  bool dumpInstructions;
  const char* inputFile;
};

static void __attribute__((noreturn))
printUsage()
{
  std::cout << "Usage: " << program_invocation_short_name <<
               " [-m {flat|callgraph}] [-d {object|symbol|source}] [-i] filename.pgdata\n";
  exit(EXIT_SUCCESS);
}

static void parseArguments(Params& params, int argc, char* argv[])
{
  int opt;
  while ((opt = getopt(argc, argv, "m:d:i")) != -1)
  {
    switch (opt)
    {
    case 'm':
      if (strcmp(optarg, "flat") == 0)
        params.mode = Profile::Flat;
      else if (strcmp(optarg, "callgraph") == 0)
        params.mode = Profile::CallGraph;
      else
      {
        std::cerr << "Invalid mode '" << optarg <<"'\n";
        exit(EXIT_FAILURE);
      }
      break;
    case 'd':
      if (strcmp(optarg, "object") == 0)
        params.details = Profile::Objects;
      else if (strcmp(optarg, "symbol") == 0)
        params.details = Profile::Symbols;
      else if (strcmp(optarg, "source") == 0)
        params.details = Profile::Sources;
      else
      {
        std::cerr << "Invalid details level '" << optarg <<"'\n";
        exit(EXIT_FAILURE);
      }
      break;
    case 'i':
      params.dumpInstructions = true;
      break;
    default:
      printUsage();
    }
  }

  if (optind >= argc)
    printUsage();
  else
    params.inputFile = argv[optind];

  // It is not possible to use callgraphs with objects only
  if (params.details == Profile::Objects)
    params.mode = Profile::Flat;
}

static void dumpCallTo(std::ostream& os, const MemoryObjectData& callObjectData, const SymbolData& callSymbolData)
{
  os << "cob=" << callObjectData.fileName()
     << "\ncfi=" << callSymbolData.sourceFile()
     << "\ncfn=" << callSymbolData.name() << '\n';
}

struct EntrySum
{
  EntrySum() : count(0) {}
  std::map<const Symbol*, Count> branches;
  Count count;
};

typedef std::map<size_t, EntrySum> ByLine;

typedef std::map<const std::string*, ByLine> ByFileByLine;

struct EntryGroupper
{
  ByFileByLine& operator()(ByFileByLine& group, const Entry& entry) const
  {
    const EntryData* entryData = entry.second;
    EntrySum& groupData = group[&entryData->sourceFile()][entryData->sourceLine()];
    groupData.count += entryData->count();

    for (BranchStorage::const_iterator branchIt = entryData->branches().begin();
         branchIt != entryData->branches().end(); ++branchIt)
      groupData.branches[branchIt->first.symbol] += branchIt->second;

    return group;
  }
};

static void dumpEntriesWithoutInstructions(std::ostream& os, const MemoryObjectStorage& objects,
                                    const std::string* fileName,
                                    EntryStorage::const_iterator entryFirst,
                                    EntryStorage::const_iterator entryLast)
{
  const ByFileByLine& total = std::accumulate(entryFirst, entryLast, ByFileByLine(), EntryGroupper());

  // We want to dump summary for current file first
  ByFileByLine::const_iterator currFileIt = total.find(fileName);
  ByFileByLine::const_iterator byFileByLineIt = currFileIt;
  if (byFileByLineIt == total.end())
    byFileByLineIt = total.begin();
  bool currentFileDone = (currFileIt == total.end());

  while (byFileByLineIt != total.end())
  {
    if (currentFileDone && byFileByLineIt == currFileIt)
    {
      ++byFileByLineIt;
      continue;
    }

    const std::string& fileName = *(byFileByLineIt->first);
    const ByLine& byLine = byFileByLineIt->second;

    if (currentFileDone)
      os << "fi=" << fileName << '\n';

    for (ByLine::const_iterator byLineIt = byLine.begin(); byLineIt != byLine.end(); ++byLineIt)
    {
      size_t line = byLineIt->first;
      const EntrySum& entrySum = byLineIt->second;

      if (entrySum.count)
        os << line << ' ' << entrySum.count << '\n';

      for (std::map<const Symbol*, Count>::const_iterator branchIt = entrySum.branches.begin();
           branchIt != entrySum.branches.end(); ++branchIt)
      {
        const Symbol* callSymbol = branchIt->first;
        const MemoryObjectData* callObjectData = objects.at(Range(callSymbol->first.start));
        dumpCallTo(os, *callObjectData, *callSymbol->second);
        os << "calls=1 " << callSymbol->second->sourceLine() << '\n';
        os << line << ' ' << branchIt->second << '\n';
      }
    }
    if (!currentFileDone)
    {
      byFileByLineIt = total.begin();
      currentFileDone = true;
    }
    else
      ++byFileByLineIt;
  }
}

static void dumpEntriesWithInstructions(std::ostream& os, const MemoryObjectStorage& objects,
                                 const std::string* fileName,
                                 int64_t addressAdjust,
                                 EntryStorage::const_iterator entryFirst,
                                 EntryStorage::const_iterator entryLast)
{
  for (; entryFirst != entryLast; ++entryFirst)
  {
    Address entryAddress = entryFirst->first - addressAdjust;
    const EntryData& entryData = *entryFirst->second;

    if (fileName != &entryData.sourceFile())
    {
      fileName = &entryData.sourceFile();
      os << "fi=" << *fileName << '\n';
    }

    if (entryData.count())
      os << "0x" << std::hex << entryAddress << std::dec << ' ' << entryData.sourceLine() << ' '
         << entryData.count() << '\n';

    for (BranchStorage::const_iterator branchIt = entryFirst->second->branches().begin();
         branchIt != entryFirst->second->branches().end(); ++branchIt)
    {
      const Symbol* callSymbol = branchIt->first.symbol;
      const MemoryObject& callObject = *objects.find(Range(callSymbol->first.start));
      Address callAddress = callSymbol->first.start - callObject.first.start + callObject.second->baseAddress();
      dumpCallTo(os, *callObject.second, *callSymbol->second);
      os << "calls=1 0x" << std::hex << callAddress << std::dec << ' ' << callSymbol->second->sourceLine() << '\n';
      os << "0x" << std::hex << entryAddress << std::dec << ' ' << entryData.sourceLine() << ' '
         << branchIt->second << '\n';
    }
  }
}

static void dump(std::ostream& os, const Profile& profile, bool dumpInstructions)
{
  os << "positions:";
  if (dumpInstructions)
    os << " instr";
  os <<" line\n";

  os << "events: Cycles\n\n";

  for (MemoryObjectStorage::const_iterator objIt = profile.memoryObjects().begin();
       objIt != profile.memoryObjects().end(); ++objIt)
  {
    const MemoryObject& object = *objIt;
    os << "ob=" << object.second->fileName() << '\n';

    const EntryStorage& entries =  object.second->entries();
    const SymbolStorage& symbols = object.second->symbols();

    const std::string* fileName = 0;

    for (SymbolStorage::const_iterator symIt = symbols.begin(); symIt != symbols.end(); ++symIt)
    {
      const Range& symbolRange = symIt->first;
      const SymbolData& symbolData = *symIt->second;

      if (!fileName || fileName != &symbolData.sourceFile())
      {
        fileName = &symbolData.sourceFile();
        os << "fl=" << *fileName << '\n';
      }
      os << "fn=" << symbolData.name() << '\n';

      EntryStorage::const_iterator entryFirst = entries.lower_bound(symbolRange.start);
      EntryStorage::const_iterator entryLast = entries.upper_bound(symbolRange.end);

      if (dumpInstructions)
      {
        int64_t addresAdjust = object.first.start - object.second->baseAddress();
        dumpEntriesWithInstructions(os, profile.memoryObjects(), fileName, addresAdjust, entryFirst, entryLast);
      }
      else
        dumpEntriesWithoutInstructions(os, profile.memoryObjects(), fileName, entryFirst, entryLast);
    }
    os << '\n';
  }
}

int main(int argc, char** argv)
{
  Params params;
  parseArguments(params, argc, argv);

  std::fstream input(params.inputFile, std::ios_base::in);
  if (!input)
  {
    std::cerr << "Error reading input file " << params.inputFile << '\n';
    exit(EXIT_FAILURE);
  }

  Profile profile;
  profile.load(input, params.mode);
  input.close();

  profile.resolveAndFixup(params.details);

  dump(std::cout, profile, params.dumpInstructions);

  return 0;
}
