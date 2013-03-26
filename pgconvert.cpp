#include "Profile.h"
#include "AddressResolver.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <numeric>
#include <cerrno>
#include <cstdlib>
#include <cstring>


struct Params
{
  Params()
    : mode(Profile::CallGraph)
    , details(Profile::Symbols)
    , dumpInstructions(false)
    , inputFile(0)
  {}
  Profile::Mode mode;
  Profile::DetailLevel details;
  bool dumpInstructions;
  const char* inputFile;
};

void parseArguments(Params& params, int argc, char* argv[])
{
  if (argc < 2)
  {
    std::cout << "Usage: " << program_invocation_short_name <<
                 " [-m {flat|callgraph}] [-d {object|symbol|source}] [-i] filename.pgdata\n";
    exit(EXIT_SUCCESS);
  }

  int nextArgType = 0;
  for (argv++; *argv; argv++)
  {
    char* argp = *argv;
    switch(nextArgType)
    {
    case 0:
      if (strcmp(argp, "-m") == 0)
        nextArgType = 1;
      else if (strcmp(argp, "-d") == 0)
        nextArgType = 2;
      else if (strcmp(argp, "-i") == 0)
        params.dumpInstructions = true;
      else
        params.inputFile = argp;
      break;
    case 1:
      // mode
      nextArgType = 0;
      if (strcmp(argp, "flat") == 0)
        params.mode = Profile::Flat;
      else if (strcmp(argp, "callgraph") == 0)
        params.mode = Profile::CallGraph;
      else
      {
        std::cerr << "Invalid mode '" << argp <<"'\n";
        exit(EXIT_FAILURE);
      }
      break;
    case 2:
      // detail
      nextArgType = 0;
      if (strcmp(argp, "object") == 0)
        params.details = Profile::Objects;
      else if (strcmp(argp, "symbol") == 0)
        params.details = Profile::Symbols;
      else if (strcmp(argp, "source") == 0)
        // Source is not supported yet
        params.details = Profile::Symbols;
      else
      {
        std::cerr << "Invalid details level '" << argp <<"'\n";
        exit(EXIT_FAILURE);
      }
    }
  }

  // It is not possible to use callgraphs with objects only
  if (params.details == Profile::Objects)
    params.mode = Profile::Flat;

  if (!params.inputFile)
  {
    std::cerr << "Not input file given\n";
    exit(EXIT_FAILURE);
  }
}

struct CountedValue
{
  CountedValue() : value(0) {}
  Count value;
};

struct EntryTotal
{
  CountedValue count;
  std::map<Address, CountedValue> branches;
};

struct EntryPlus
{
  EntryTotal& operator()(EntryTotal& first, const Entry& second) const
  {
    first.count.value += second.second->count();
    for (BranchStorage::const_iterator branchIt = second.second->branches().begin();
         branchIt != second.second->branches().end(); ++branchIt)
      first.branches[branchIt->first].value += branchIt->second;
    return first;
  }
};

void dump(std::ostream& os, const Profile& profile, const Params& params)
{
  os << "positions:";
  if (params.dumpInstructions)
    os << " instr";
  os << " line\n";

  os << "events: Cycles\n\n";

  for (MemoryObjectStorage::const_iterator objIt = profile.memoryObjects().begin();
       objIt != profile.memoryObjects().end(); ++objIt)
  {
    const MemoryObject& object = *objIt;
    os << "ob=" << object.second->fileName() << '\n';

    const EntryStorage& entries =  object.second->entries();
    const SymbolStorage& symbols = object.second->symbols();

    for (SymbolStorage::const_iterator symIt = symbols.begin(); symIt != symbols.end(); ++symIt)
    {
      const Symbol& symbol = *symIt;
      os << "fn=" << symbol.second->name() << '\n';

      EntryStorage::const_iterator entryFirst = entries.lower_bound(symbol.first.start);
      EntryStorage::const_iterator entryLast = entries.upper_bound(symbol.first.end);

      if (params.dumpInstructions)
      {
        for (; entryFirst != entryLast; ++entryFirst)
          if (entryFirst->second->count())
            os << "0x" << std::hex << entryFirst->first - object.first.start + object.second->baseAddress()
               << " 0 " << std::dec << entryFirst->second->count() << '\n';
      }
      else
      {
        const EntryTotal& total = std::accumulate(entryFirst, entryLast, EntryTotal(), EntryPlus());
        if (total.count.value)
          os << "0 " << total.count.value << '\n';
        for (std::map<Address, CountedValue>::const_iterator branchIt = total.branches.begin();
             branchIt != total.branches.end(); ++branchIt)
        {
          const MemoryObjectData* callObjectData = profile.memoryObjects().find(Range(branchIt->first))->second;
          os << "cob=" << callObjectData->fileName() << '\n';
          const SymbolData* callSymbolData = callObjectData->symbols().find(Range(branchIt->first))->second;
          os << "cfn=" << callSymbolData->name() << '\n';
          os << "calls=1 0\n0 " << branchIt->second.value << '\n';
        }
        entryFirst = entryLast;
      }
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
    std::cerr << "Error reading input file " << argv[1] << '\n';
    exit(EXIT_FAILURE);
  }

  Profile profile;
  profile.load(input, params.mode);
  input.close();

  profile.resolveAndFixup(params.details);

  dump(std::cout, profile, params);

  return 0;
}
