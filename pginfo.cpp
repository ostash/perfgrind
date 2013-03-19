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

  std::cout << "memory objects: " << profile.memoryObjects().size()
     << "\nentries: " << profile.entries().size()
     << "\n\ngood sample events: " << profile.goodSamplesCount()
     << "\nbad sample events: " << profile.badSamplesCount()
     << "\ntotal sample events: " << profile.goodSamplesCount() + profile.badSamplesCount()
     << "\ntotal events: " << profile.goodSamplesCount() + profile.badSamplesCount() + profile.memoryObjects().size()
     << '\n';

  return 0;
}
