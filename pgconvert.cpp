#include "Profile.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <numeric>

#include <argp.h>

struct Params
{
  ProfileMode mode = ProfileMode::CallGraph;
  ProfileDetails details = ProfileDetails::Sources;
  bool dumpInstructions = false;
  const char* inputFile = nullptr;
  const char* outputFile = nullptr;

  bool modeSet = false;
  bool detailsSet = false;
  bool instrSet = false;
  bool outputSet = false;
};

static const struct argp_option convertOptions[] = {
  {"details", 'd', "LEVEL", 0, "Detail level: object, symbol or source (default: source)", 0},
  {"instructions", 'i', nullptr, 0, "Include instruction addresses in output", 0},
  {"mode", 'm', "MODE", 0, "Profile mode: flat or callgraph (default: callgraph)", 0},
  {"output", 'o', "FILE", 0, "Write output to FILE instead of stdout", 0},
  {nullptr, 0, nullptr, 0, nullptr, 0}};

static const char convertArgsDoc[] = "INPUT.pgdata";
static const char convertDoc[] = "Convert perfgrind profile data to callgrind format.";

static error_t convertParseOpt(int key, char* arg, struct argp_state* state)
{
  Params* params = static_cast<Params*>(state->input);
  switch (key)
  {
  case 'm':
    if (params->modeSet)
      argp_error(state, "option -m/--mode given more than once");
    params->modeSet = true;
    if (strcmp(arg, "flat") == 0)
      params->mode = ProfileMode::Flat;
    else if (strcmp(arg, "callgraph") == 0)
      params->mode = ProfileMode::CallGraph;
    else
      argp_error(state, "invalid mode '%s'; expected 'flat' or 'callgraph'", arg);
    break;
  case 'd':
    if (params->detailsSet)
      argp_error(state, "option -d/--details given more than once");
    params->detailsSet = true;
    if (strcmp(arg, "object") == 0)
      params->details = ProfileDetails::Objects;
    else if (strcmp(arg, "symbol") == 0)
      params->details = ProfileDetails::Symbols;
    else if (strcmp(arg, "source") == 0)
      params->details = ProfileDetails::Sources;
    else
      argp_error(state, "invalid detail level '%s'; expected 'object', 'symbol' or 'source'", arg);
    break;
  case 'i':
    if (params->instrSet)
      argp_error(state, "option -i/--instr given more than once");
    params->instrSet = true;
    params->dumpInstructions = true;
    break;
  case 'o':
    if (params->outputSet)
      argp_error(state, "option -o/--output given more than once");
    params->outputSet = true;
    params->outputFile = arg;
    break;
  case ARGP_KEY_ARG:
    if (state->arg_num > 0)
      argp_usage(state);
    params->inputFile = arg;
    break;
  case ARGP_KEY_END:
    if (!params->inputFile)
      argp_usage(state);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp convertArgp = {convertOptions, convertParseOpt, convertArgsDoc, convertDoc,
                                        nullptr,        nullptr,         nullptr};

static Params parseArguments(int argc, char* argv[])
{
  Params params;
  argp_parse(&convertArgp, argc, argv, 0, nullptr, &params);
  // It is not possible to use callgraphs with objects only
  if (params.details == ProfileDetails::Objects)
    params.mode = ProfileMode::Flat;

  return params;
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
    const EntryData& entryData = entry.second;
    EntrySum& groupData = group[&entryData.sourceFile()][entryData.sourceLine()];
    groupData.count += entryData.count();

    for (const auto& branch: entryData.branches())
      groupData.branches[branch.first.symbol] += branch.second;

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

    for (const auto& byLineElem: byLine)
    {
      const size_t line = byLineElem.first;
      const EntrySum& entrySum = byLineElem.second;

      if (entrySum.count)
        os << line << ' ' << entrySum.count << '\n';

      for (const auto& branch: entrySum.branches)
      {
        const Symbol* callSymbol = branch.first;
        const MemoryObjectData& callObjectData = objects.at(Range(callSymbol->first.start()));
        dumpCallTo(os, callObjectData, callSymbol->second);
        os << "calls=1 " << callSymbol->second.sourceLine() << '\n';
        os << line << ' ' << branch.second << '\n';
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

static void dumpEntriesWithInstructions(std::ostream& os, const MemoryObject& currentObject,
                                        const MemoryObjectStorage& allObjects, const std::string* fileName,
                                        EntryStorage::const_iterator entryFirst, EntryStorage::const_iterator entryLast)
{
  for (; entryFirst != entryLast; ++entryFirst)
  {
    Address entryAddress = currentObject.second.mapToElf(currentObject.first.start(), entryFirst->first);
    const EntryData& entryData = entryFirst->second;

    if (fileName != &entryData.sourceFile())
    {
      fileName = &entryData.sourceFile();
      os << "fi=" << *fileName << '\n';
    }

    if (entryData.count())
      os << "0x" << std::hex << entryAddress << std::dec << ' ' << entryData.sourceLine() << ' '
         << entryData.count() << '\n';

    for (const auto& branch: entryFirst->second.branches())
    {
      const Symbol* callSymbol = branch.first.symbol;
      const MemoryObject& callObject = *allObjects.find(Range(callSymbol->first.start()));
      Address callAddress = callObject.second.mapToElf(callObject.first.start(), callSymbol->first.start());
      dumpCallTo(os, callObject.second, callSymbol->second);
      os << "calls=1 0x" << std::hex << callAddress << std::dec << ' ' << callSymbol->second.sourceLine() << '\n';
      os << "0x" << std::hex << entryAddress << std::dec << ' ' << entryData.sourceLine() << ' ' << branch.second
         << '\n';
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

  for (const auto& object: profile.memoryObjects())
  {
    os << "ob=" << object.second.fileName() << '\n';

    const EntryStorage& entries = object.second.entries();
    const SymbolStorage& symbols = object.second.symbols();

    const std::string* fileName = 0;

    for (const auto& symbol: symbols)
    {
      const Range& symbolRange = symbol.first;
      const SymbolData& symbolData = symbol.second;

      if (!fileName || fileName != &symbolData.sourceFile())
      {
        fileName = &symbolData.sourceFile();
        os << "fl=" << *fileName << '\n';
      }
      os << "fn=" << symbolData.name() << '\n';

      EntryStorage::const_iterator entryFirst = entries.lower_bound(symbolRange.start());
      EntryStorage::const_iterator entryLast = entries.upper_bound(symbolRange.end());

      if (dumpInstructions)
      {
        dumpEntriesWithInstructions(os, object, profile.memoryObjects(), fileName, entryFirst, entryLast);
      }
      else
        dumpEntriesWithoutInstructions(os, profile.memoryObjects(), fileName, entryFirst, entryLast);
    }
    os << '\n';
  }
}

int main(int argc, char** argv)
{
  Params params = parseArguments(argc, argv);

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

  if (params.outputFile)
  {
    std::ofstream out (params.outputFile);
    if (!out)
    {
      std::cerr << "Can't write to the output file " << params.outputFile << '\n';
      exit(EXIT_FAILURE);
    }
    dump(out, profile, params.dumpInstructions);
  }
  else
    dump(std::cout, profile, params.dumpInstructions);

  return 0;
}
