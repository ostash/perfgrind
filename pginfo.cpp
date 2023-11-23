#include "Profile.h"

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

  ProfileMode mode;
  if (strcmp(argv[1], "flat") == 0)
    mode = ProfileMode::Flat;
  else if (strcmp(argv[1], "callgraph") == 0)
    mode = ProfileMode::CallGraph;
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

  size_t entryCount = 0;
  for (const auto& memoryObject: profile.memoryObjects())
    entryCount += memoryObject.second.entries().size();

  std::cout << "memory objects: " << profile.memoryObjects().size() << "\nentries: " << entryCount
            << "\n\nmmap events: " << profile.mmapEventCount() << "\ngood sample events: " << profile.goodSamplesCount()
            << "\nnon-user sample events: " << profile.nonUserSamples()
            << "\nunmapped sample events: " << profile.unmappedSamples() << "\ntotal sample events: "
            << profile.goodSamplesCount() + profile.nonUserSamples() + profile.unmappedSamples() << "\ntotal events: "
            << profile.goodSamplesCount() + profile.goodSamplesCount() + profile.nonUserSamples() +
                 profile.unmappedSamples()
            << '\n';

  return 0;
}
