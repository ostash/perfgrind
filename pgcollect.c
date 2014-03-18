#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#include <linux/perf_event.h>

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

struct PGCollectState
{
  pid_t* pids;
  FILE* output;
  size_t taskCount;
  unsigned frequency;
  int gogoFD;
  unsigned wakeupCount;
  unsigned sampleCount;
  unsigned mmapCount;
  unsigned synthMmapCount;
};

struct PerfMmapArea
{
  __u64 prev;
  struct perf_event_mmap_page* header;
  char* data;
  size_t mask;
};

volatile sig_atomic_t stopCollecting = 0;

static void signalHandler(int sigNo)
{
  stopCollecting = 1;
}

static void setupSignalHandlers(sighandler_t handler)
{
  signal(SIGINT, handler);
  signal(SIGCHLD, handler);
}

static void collectTasks(struct PGCollectState* state, pid_t pid)
{
  char taskPath[PATH_MAX];
  snprintf(taskPath, sizeof(taskPath), "/proc/%lld/task", (long long)pid);

  DIR* taskDir = opendir(taskPath);
  if (!taskDir)
  {
    fprintf(stderr, "Can't open task directory %s: %s\n", taskPath, strerror(errno));
    exit(EXIT_FAILURE);
  }

  size_t taskAlloc = 1024;
  state->pids = malloc(taskAlloc * sizeof(pid));
  state->taskCount = 0;

  struct dirent* task;
  while ((task = readdir(taskDir)) != 0)
  {
    pid_t taskPid = strtoll(task->d_name, 0, 10);
    if (!taskPid)
      continue;
    state->pids[state->taskCount] = taskPid;
    state->taskCount++;
    if (state->taskCount >= taskAlloc)
      state->pids = realloc(state->pids, (taskAlloc += 1024) * sizeof(pid_t));
  }

  closedir(taskDir);
}

static void collectExistingMappings(struct PGCollectState* state)
{
  struct mmap_event {
      struct perf_event_header header;
      __u32    pid, tid;
      __u64    addr;
      __u64    len;
      __u64    pgoff;
      char   filename[PATH_MAX];
  };

  char mapFileName[PATH_MAX];
  snprintf(mapFileName, sizeof(mapFileName), "/proc/%lld/maps", (long long)state->pids[0]);

  FILE *mapFile = fopen(mapFileName, "r");
  if (mapFile == 0)
  {
    fprintf(stderr, "Can't open map file %s: %s\n", mapFileName, strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct mmap_event event;
  event.header.type = PERF_RECORD_MMAP;
  event.header.misc = PERF_RECORD_MISC_USER;
  event.pid = state->pids[0];
  event.tid = state->pids[0];

  while (1)
  {
    char buf[2 * PATH_MAX];

    if (fgets(buf, sizeof(buf), mapFile) == 0)
      break;

    char prot[5];
    event.filename[0] = 0;
    // 08048000-08053000 r-xp 00000000 08:03 390746 /bin/cat
    sscanf(buf, "%"PRIx64"-%"PRIx64" %s %"PRIx64" %*x:%*x %*u %s\n", &event.addr, &event.len, prot, &event.pgoff,
           event.filename);

    if (prot[2] != 'x')
      continue;

    event.len -= event.addr;
    if (event.filename[0] == 0)
      strcpy(event.filename, "[anon]");

    size_t filenameLen = strlen(event.filename) + 1; // Keep at least one NULL character
    size_t alignedFilenameLen = filenameLen % 8 ? (filenameLen / 8 + 1) * 8 : filenameLen;
    memset(event.filename + filenameLen, 0, alignedFilenameLen - filenameLen);
    event.header.size = sizeof(struct mmap_event) - PATH_MAX + alignedFilenameLen;

    fwrite(&event, event.header.size, 1, state->output);
    state->synthMmapCount++;
  }

  fclose(mapFile);
}


static void __attribute__((noreturn))
printUsage()
{
  fprintf(stdout, "Usage: %s outfile.pgdata [-F freq] {-p pid | [--] cmd}\n", program_invocation_short_name);
  exit(EXIT_SUCCESS);
}

static void prepareState(struct PGCollectState* state, int argc, char** argv)
{
  state->frequency = 1000;
  state->wakeupCount = 0;
  state->sampleCount = 0;
  state->mmapCount = 0;
  state->synthMmapCount = 0;

  int opt;
  pid_t pid = 0;
  while ((opt = getopt(argc, argv, "F:p:")) != -1)
  {
    switch (opt)
    {
    case 'F':
      state->frequency = strtoul(optarg, NULL, 10);
      break;
    case 'p': {
      state->gogoFD = -1;
      errno = 0;
      char* endptr;
      pid = strtoll(optarg, &endptr, 10);
      if (errno != 0 || *endptr != 0)
      {
        fprintf(stderr, "Bad PID '%s': %s\n", optarg, strerror(errno));
        exit(EXIT_FAILURE);
      }}
      break;
    default:
      printUsage();
    }
  }

  // We still need output file and command to run for non-pid mode
  if (argc - optind < (state->gogoFD == -1 ? 1 : 2))
    printUsage();

  state->output = fopen(argv[optind], "w");
  if (!state->output)
  {
    fprintf(stderr, "Can't create output file %s: %s\n", *argv, strerror(errno));
    exit(EXIT_FAILURE);
  }
  ++optind;

  fprintf(stdout, "Setting frequency to %u\n", state->frequency);

  if (state->gogoFD == -1)
  {
    fprintf(stdout, "Going to profile process with PID %lld\n", (long long)pid);
    collectTasks(state, pid);
    collectExistingMappings(state);
  }
  else
  {
    int childReadiness[2], profilingStart[2];
    if (pipe2(childReadiness, O_CLOEXEC) != 0 || pipe2(profilingStart, O_CLOEXEC) != 0)
    {
      perror("Can't create pipe");
      exit(EXIT_FAILURE);
    }

    state->gogoFD = profilingStart[1];

    state->taskCount = 1;
    state->pids = malloc(sizeof(pid_t));
    state->pids[0] = fork();
    if (state->pids[0] == -1)
    {
      perror("Can't fork");
      exit(EXIT_FAILURE);
    }

    if (state->pids[0] == 0)
    {
      // Child actions

      // No need to close unneeded ends of pipes as they will be closed on exec,
      // thanks to O_CLOCEXEC
      close(childReadiness[0]);
      close(profilingStart[1]);
      // Notify parent that we are ready
      close(childReadiness[1]);

      char start = 0;
      if (read(profilingStart[0], &start, 1) == -1)
      {
        perror("Can't read from pipe in child");
        exit(EXIT_FAILURE);
      }

      if (start)
      {
        execvp(argv[optind], argv + optind);
        perror("Can't exec new process");
      }

      exit(EXIT_FAILURE);
    }
    else
    {
      // Parent actions
      close(childReadiness[1]);
      close(profilingStart[0]);

      // Wait for child to be created
      char buf;
      if (read(childReadiness[0], &buf, 1) == -1)
      {
        perror("Can't read from pipe in parent");
        close(profilingStart[1]);
        exit(EXIT_FAILURE);
      }
      close(childReadiness[0]);

      fprintf(stdout, "Going to profile process with PID %lld: ", (long long)state->pids[0]);
      while (optind < argc)
        fprintf(stdout, "%s ", argv[optind++]);
      fputc('\n', stdout);
    }
  }
}

static int createPerfEvent(const struct PGCollectState* state, pid_t pid, int cpu)
{
  struct perf_event_attr pe_attr;
  memset(&pe_attr, 0, sizeof(struct perf_event_attr));

  bool forkMode = (state->gogoFD != -1);

  pe_attr.type = PERF_TYPE_HARDWARE;
//  pe_attr.type = PERF_TYPE_SOFTWARE;
  pe_attr.size = sizeof(struct perf_event_attr);
  pe_attr.config = PERF_COUNT_HW_CPU_CYCLES;
//  pe_attr.config = PERF_COUNT_SW_CPU_CLOCK;
  pe_attr.sample_freq = state->frequency;
  pe_attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
  pe_attr.disabled = forkMode;
  pe_attr.inherit = forkMode;
  pe_attr.exclude_kernel = 1;
  pe_attr.exclude_hv = 1;
  pe_attr.mmap = 1;
  pe_attr.freq = 1;
  pe_attr.enable_on_exec = forkMode;
  pe_attr.task = 1;
//  pe_attr.precise_ip = 2;

  // Wake for every Xth event
//  pe_attr.wakeup_events = 5;

  int fd = perf_event_open(&pe_attr, pid, cpu, -1, 0);
  if (fd == -1)
  {
    perror("Can't create performance event file descriptor");
    if (state->gogoFD != -1)
      close(state->gogoFD);
    exit(EXIT_FAILURE);
  }

  if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
  {
    perror("Can't fcntl on performance event file descriptor");
    if (state->gogoFD != -1)
      close(state->gogoFD);
    exit(EXIT_FAILURE);
  }

  return fd;
}

static void mmapPerfEvent(struct PerfMmapArea* area, int perfEventFD, const struct PGCollectState* state)
{
  // TODO: read limit from /proc/sys/kernel/perf_event_mlock_kb
  // and don't assume that 512k is allways 2^n pages
  long pageSize = sysconf(_SC_PAGESIZE);
  size_t size = 512 * 1024 + pageSize;

  area->header = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, perfEventFD, 0);
  if (area->header == MAP_FAILED)
  {
    perror("Can't mmap perf events");
    if (state->gogoFD != -1)
      close(state->gogoFD);
    exit(EXIT_FAILURE);
  }

  area->data = ((char*)(area->header)) + pageSize;
  area->prev = 0;
  area->mask = size - pageSize -1;
}

static void fillPollData(struct pollfd* pollData, int perfEventFD)
{
  pollData->fd = perfEventFD;
  pollData->events = POLLIN;
}

static void pingProfiledProcess(int gogoFD)
{
  char buf = 1;
  if (write(gogoFD, &buf, 1) == -1)
  {
    perror("Can't write to pipe in parent");
    exit(EXIT_FAILURE);
  }
  close(gogoFD);
}

// Some magic taken from tools/perf
#if defined(__i386__)
#define rmb() asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
#endif

#if defined(__x86_64__)
#define rmb() asm volatile("lfence" ::: "memory")
#endif

static void processEvents(struct PerfMmapArea* area, struct PGCollectState* state)
{
  // Read head
  __u64 head = area->header->data_head;
  rmb();

  if (area->prev == head)
    return;

  while (area->prev != head)
  {
    struct perf_event_header* eventHeader = (struct perf_event_header*)&(area->data[area->prev & area->mask]);

    if (eventHeader->type == PERF_RECORD_MMAP || eventHeader->type == PERF_RECORD_SAMPLE)
    {
      if (eventHeader->type == PERF_RECORD_MMAP)
        state->mmapCount++;
      else if (eventHeader->type == PERF_RECORD_SAMPLE)
        state->sampleCount++;

      if ((area->prev & area->mask) + eventHeader->size != ((area->prev + eventHeader->size) & area->mask))
      {
        size_t dataSize = area->mask + 1;
        size_t offset = area->prev & area->mask;
        size_t chunkSize = dataSize - offset;
        fwrite(eventHeader, chunkSize, 1,  state->output);
        fwrite(area->data, eventHeader->size - chunkSize, 1, state->output);
      }
      else
        fwrite(eventHeader, eventHeader->size, 1, state->output);
    }

    area->prev += eventHeader->size;

    // Set tail
    area->header->data_tail = head;
  }
}

int main(int argc, char** argv)
{
  struct PGCollectState state;
  prepareState(&state, argc, argv);

  int eventFdCount = 0;
  // In fork mode we open one fd per cpu
  // In follow mode we open one fd per task
  if (state.gogoFD != -1)
    eventFdCount = sysconf(_SC_NPROCESSORS_ONLN);
  else
    eventFdCount = state.taskCount;

  int perfEventFD[eventFdCount];
  struct PerfMmapArea perfEventArea[eventFdCount];
  struct pollfd pollData[eventFdCount];

  if (state.gogoFD != -1)
    for (int cpu = 0; cpu < eventFdCount; cpu++)
      perfEventFD[cpu] = createPerfEvent(&state, state.pids[0], cpu);
  else
    for (int pidId = 0; pidId < eventFdCount; pidId++)
      perfEventFD[pidId] = createPerfEvent(&state, state.pids[pidId], -1);

  for (int eventFdIdx = 0; eventFdIdx < eventFdCount; eventFdIdx++)
  {
    mmapPerfEvent(&perfEventArea[eventFdIdx], perfEventFD[eventFdIdx], &state);
    fillPollData(&pollData[eventFdIdx], perfEventFD[eventFdIdx]);
  }

  setupSignalHandlers(signalHandler);

  if (state.gogoFD != -1)
    pingProfiledProcess(state.gogoFD);

  while (1)
  {
    for (int eventFdIdx = 0; eventFdIdx < eventFdCount; eventFdIdx++)
      processEvents(&perfEventArea[eventFdIdx], &state);

    if (stopCollecting)
      break;

    if (poll(pollData, eventFdCount, -1) == -1 && errno != EINTR)
    {
      perror("Poll error");
      stopCollecting = 1;
    }
    state.wakeupCount++;
  }

  setupSignalHandlers(SIG_DFL);
  // Stop child
  if (state.gogoFD != -1)
    kill(state.pids[0], SIGTERM);

  puts("Collection stopped.");
  fclose(state.output);
  fprintf(stdout, "Waked up %u times\nSythetic mmap events: %u\nReal mmap events: %u\nSample events: %u\n",
          state.wakeupCount, state.synthMmapCount, state.mmapCount, state.sampleCount);
  fprintf(stdout, "Total %u events written\n", state.synthMmapCount + state.mmapCount + state.sampleCount);
}
