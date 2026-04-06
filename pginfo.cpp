#include "Profile.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

#include <argp.h>

struct PGInfoArgs
{
  ProfileMode mode = ProfileMode::CallGraph;
  bool modeSet = false;
  const char* inputFile = nullptr;
};

static const struct argp_option infoOptions[] = {
  {"mode", 'm', "MODE", 0, "Profile mode: flat or callgraph (default: callgraph)", 0},
  {nullptr, 0, nullptr, 0, nullptr, 0}};

static const char infoArgsDoc[] = "INPUT.pgdata";
static const char infoDoc[] = "Display statistics for a perfgrind profile.";

static error_t infoParseOpt(int key, char* arg, struct argp_state* state)
{
  PGInfoArgs* args = static_cast<PGInfoArgs*>(state->input);
  switch (key)
  {
  case 'm':
    if (args->modeSet)
      argp_error(state, "option -m/--mode given more than once");
    args->modeSet = true;
    if (strcmp(arg, "flat") == 0)
      args->mode = ProfileMode::Flat;
    else if (strcmp(arg, "callgraph") == 0)
      args->mode = ProfileMode::CallGraph;
    else
      argp_error(state, "invalid mode '%s'; expected 'flat' or 'callgraph'", arg);
    break;
  case ARGP_KEY_ARG:
    if (state->arg_num > 0)
      argp_usage(state);
    args->inputFile = arg;
    break;
  case ARGP_KEY_END:
    if (!args->inputFile)
      argp_usage(state);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp infoArgp = {infoOptions, infoParseOpt, infoArgsDoc, infoDoc, nullptr, nullptr, nullptr};

int main(int argc, char** argv)
{
  PGInfoArgs pgInfoArgs;
  argp_parse(&infoArgp, argc, argv, 0, nullptr, &pgInfoArgs);
  const ProfileMode mode = pgInfoArgs.mode;

  std::fstream input(pgInfoArgs.inputFile, std::ios_base::in);
  if (!input)
  {
    std::cerr << "Error reading input file " << pgInfoArgs.inputFile << '\n';
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
            << profile.mmapEventCount() + profile.goodSamplesCount() + profile.nonUserSamples() +
                 profile.unmappedSamples()
            << '\n';

  return 0;
}
