#include "Profile.h"
#include "AddressResolver.h"

#include <fstream>
#include <iostream>
#include <cerrno>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv)
{
  if (argc < 3)
  {
    std::cout << "Usage: " << program_invocation_short_name << " {flat|callgraph} filename.pgdata\n";
    exit(EXIT_SUCCESS);
  }

  Profile::Mode mode;
  if (strcmp(argv[1], "flat") == 0)
    mode = Profile::Flat;
  else if (strcmp(argv[1], "callgraph") == 0)
    mode = Profile::CallGraph;
  else
  {
    std::cerr << "Invalid mode '" << argv[1] <<"'\n";
    exit(EXIT_FAILURE);
  }

  std::fstream input(argv[2], std::ios_base::in);
  if (!input)
  {
    std::cerr << "Error reading input file " << argv[1] << '\n';
    exit(EXIT_FAILURE);
  }

  Profile profile;
  profile.load(input, mode);
  input.close();

  for (MemoryObjectStorage::const_iterator objIt = profile.memoryObjects().begin();
       objIt != profile.memoryObjects().end(); ++objIt)
  {
    EntryStorage::const_iterator lowerIt = profile.entries().lower_bound(objIt->first.start);
    EntryStorage::const_iterator upperIt = profile.entries().upper_bound(objIt->first.end);
    if (lowerIt != upperIt)
    {
      AddressResolver r(objIt->second.fileName().c_str(), objIt->first.end - objIt->first.start);
      r.resolve(lowerIt, upperIt, objIt->first.start, profile.symbols());
    }
  }

  if (mode == Profile::CallGraph)
    profile.fixupBranches();

  return 0;
}
