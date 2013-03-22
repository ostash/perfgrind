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
    , details(AddressResolver::Symbols)
    , dumpInstructions(false)
    , inputFile(0)
  {}
  Profile::Mode mode;
  AddressResolver::DetailLevel details;
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
        params.details = AddressResolver::Objects;
      else if (strcmp(argp, "symbol") == 0)
        params.details = AddressResolver::Symbols;
      else if (strcmp(argp, "source") == 0)
        // Source is not supported yet
        params.details = AddressResolver::Symbols;
      else
      {
        std::cerr << "Invalid details level '" << argp <<"'\n";
        exit(EXIT_FAILURE);
      }
    }
  }

  if (!params.inputFile)
  {
    std::cerr << "Not input file given\n";
    exit(EXIT_FAILURE);
  }
}

struct CountSum
{
  Count operator()(Count first, Entry second) const
  {
    return first + second.second.count();
  }
};

void dump(std::ostream& os, const Profile& profile, const Params& params)
{
  // m=flat, d=object
  os << "positions:";
  if (params.dumpInstructions)
    os << " instr";
  os << " line\n";

  os << "events: Cycles\n\n";

  const SymbolStorage& symbols = profile.symbols();
  SymbolStorage::const_iterator symFirst = symbols.begin();

  const EntryStorage& entries =  profile.entries();
  EntryStorage::const_iterator entryFirst = entries.begin();

  for (MemoryObjectStorage::const_iterator objIt = profile.memoryObjects().begin();
       objIt != profile.memoryObjects().end(); ++objIt)
  {
    const MemoryObject& object = *objIt;
    os << "ob=" << object.second.fileName() << '\n';

    symFirst = std::lower_bound(symFirst, symbols.end(), object.first.start);
    SymbolStorage::const_iterator symLast = std::upper_bound(symFirst, symbols.end(), object.first.end);
    while (symFirst != symLast)
    {
      const Symbol& symbol = *symFirst;
      os << "fn=" << symbol.second.name() << '\n';

      entryFirst = std::lower_bound(entryFirst, entries.end(), symbol.first.start);
      EntryStorage::const_iterator entryLast = std::upper_bound(entryFirst, entries.end(), symbol.first.end);

      if (params.dumpInstructions)
      {
        for (; entryFirst != entryLast; ++entryFirst)
          os << "0x" << std::hex << entryFirst->first - object.first.start + object.second.baseAddress()
             << " 0 " << std::dec << entryFirst->second.count() << '\n';
      }
      else
      {
        Count total = std::accumulate(entryFirst, entryLast, 0, CountSum());
        os << "0 " << total << '\n';
        entryFirst = entryLast;
      }

      ++symFirst;
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

  for (MemoryObjectStorage::iterator objIt = profile.memoryObjects().begin();
       objIt != profile.memoryObjects().end(); ++objIt)
  {
    EntryStorage::const_iterator lowerIt = profile.entries().lower_bound(objIt->first.start);
    EntryStorage::const_iterator upperIt = profile.entries().upper_bound(objIt->first.end);
    if (lowerIt != upperIt)
    {
      AddressResolver r(params.details, objIt->second.fileName().c_str(), objIt->first.end - objIt->first.start);
      r.resolve(lowerIt, upperIt, objIt->first.start, profile.symbols());
      objIt->second.setBaseAddress(r.baseAddress());
    }
  }

  if (params.mode == Profile::CallGraph)
    profile.fixupBranches();

  dump(std::cout, profile, params);

  return 0;
}
