#include "Profile.h"
#include "AddressResolver.h"

#include <fstream>
#include <iostream>
#include <numeric>
#include <cerrno>
#include <cstdlib>
#include <cstring>


struct Params
{
  enum Detail
  {
    Object,
    Symbol,
    Source
  };
  Params()
    : mode(Profile::CallGraph)
    , detail(Symbol)
    , dumpInstructions(false)
    , inputFile(0)
  {}
  Profile::Mode mode;
  Detail detail;
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
        params.detail = Params::Object;
      else if (strcmp(argp, "symbol") == 0)
        params.detail = Params::Symbol;
      else if (strcmp(argp, "source") == 0)
        // Source is not supported yet
        params.detail = Params::Symbol;
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

  for (MemoryObjectStorage::const_iterator objIt = profile.memoryObjects().begin();
       objIt != profile.memoryObjects().end(); ++objIt)
  {
    EntryStorage::const_iterator lowerIt = profile.entries().lower_bound(objIt->first.start);
    EntryStorage::const_iterator upperIt = profile.entries().upper_bound(objIt->first.end);
    if (lowerIt != upperIt)
    {
      os << "ob=" << objIt->second.fileName() << '\n';
      if (params.dumpInstructions)
      {
        for (; lowerIt != upperIt; ++lowerIt)
          os << "0x" << std::hex << lowerIt->first - objIt->first.start + objIt->second.baseAddress()
             << " 0 " << std::dec << lowerIt->second.count() << '\n';
      }
      else
      {
        Count total = std::accumulate(lowerIt, upperIt, 0, CountSum());
        os << "0 " << total << '\n';
      }
      os << '\n';
    }
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
      AddressResolver r(objIt->second.fileName().c_str(), objIt->first.end - objIt->first.start);
      r.resolve(lowerIt, upperIt, objIt->first.start, profile.symbols());
      objIt->second.setBaseAddress(r.baseAddress());
    }
  }

  if (params.mode == Profile::CallGraph)
    profile.fixupBranches();

  dump(std::cout, profile, params);

  return 0;
}