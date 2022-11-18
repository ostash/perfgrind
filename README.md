# perfgrind

This is 'perfgrind', tools for collecting samples from Linux performance events
subsystem and converting profiling data to callgrind format, allowing it to be read with KCachegrind.

Because of its own simplified format containing only the data necessary for creating the callgrind profile, the resulting file is commonly much smaller.
One additional reason is that perfgrind explicitly ignores the kernel space during profiling.

Note: Perfgrind has a known limitation which is on the TODO list - it currently does not handle
separate debug (neither on disk nor via debuginfod). Compiling with debug info and collecting data
from non-stripped binaries will provide you with useful tracing data; especially when calling into
system libraries you may see entries like `func_7f2192e087070` in ld-2.31.so and similar.


# License

This software is available to everyone under the license [GPLv2](COPYING).  
It uses parts of code derived from:

- [Linux kernel](https://www.kernel.org), license is GPLv2
- [elfutils](https://sourceware.org/elfutils/),
  license is GPLv3 or GPLv2 or LGPLv2


# Usage

## Overview
- collect samples using `pgcollect` into perfgrind format
- convert collected samples into callgrind format using `pgconvert`
- open resulting file in KCachegrind

## `pgcollect` - collect samples
Usage: `pgcollect filename.pgdata [-F freq] [-s] {-p pid | [--] cmd}`

Options to specify output:
- `filename.pgdata` name of output file

Options to adjust profiling:
- `-F freq` profile at the given frequency _freq_
- `-s` profile using software events

Options to specify target:
- `-p pid` profile running process with PID=_pid_
- `cmd` command to profile, prefix with `--` to stop command line parsing

## `pgconvert` - convert collected samples to callgrind format
Usage: `pgconvert [-m {flat|callgraph}] [-d {object|symbol|source}] [-i] filename.pgdata`  
Examples:
- overview showing call stack  
  `pgconvert -d symbol filename.pgdata > callgrind.out.overfiew_pgdata`
- full data with source annotation and instructions  
  `pgconvert -i filename.pgdata > callgrind.out.full_pgdata`

Options to adjust generated callgrind data:
- `-d` specify detail level; default is "source"
- `-i` dump instructions, only possible with detail level "source"
- `-m mode` default _mode_ is "callgraph" if detail level is not "object"

Note: To collect with hardware counters you may have to adjust the kernel parameter
`perf_event_paranoid` as root.

## `pginfo` - show event count and calculated entries 
Usage: `pginfo {flat|callgraph} filename.pgdata`

- `flat` simple calculation, fast way to show number of events
- `callgraph` full calculation

# Building

## Dependency [elfutils](https://sourceware.org/elfutils/)
either install from source or - preferably - via package manager, for example by issuing `sudo yum install elfutils-devel` or `sudo apt install libelf-dev`

## Building the source
- optional step: create site.mak file and set FLAGS variable with paths to elfutils header and libraries (necessary if using a "local" version of elfutils)  
  For example:  
  `FLAGS=-I/usr/local/elfutils/include -L/usr/local/elfutils/lib -O2 -march=native -Wl,-rpath /usr/local/elfutils/lib`
- build it by issuing `make`
- optional: run tests with `make check`
- optional: install binaries to enable use by others with `make install`
