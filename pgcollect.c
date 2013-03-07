#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <linux/perf_event.h>

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

struct PGCollectState
{
  pid_t pid;
  int gogoFD;
  FILE* output;
  __u64 eventCount;
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
  snprintf(mapFileName, sizeof(mapFileName), "/proc/%d/maps", state->pid);

  FILE *mapFile = fopen(mapFileName, "r");
  if (mapFile == 0)
  {
    fprintf(stderr, "Can't open map file %s: %s\n", mapFileName, strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct mmap_event event;
  event.header.type = PERF_RECORD_MMAP;
  event.header.misc = PERF_RECORD_MISC_USER;
  event.pid = state->pid;
  event.tid = state->pid;

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
  }

  fclose(mapFile);
}

static void prepareState(struct PGCollectState* state, int argc, char** argv)
{
  if (argc < 3)
  {
    fprintf(stdout, "Usage: %s outfile.pdata {-p pid | cmd}\n", program_invocation_short_name);
    exit(EXIT_SUCCESS);
  }

  state->eventCount = 0;

  state->output = fopen(argv[1], "w");
  if (!state->output)
  {
    fprintf(stderr, "Can't create output file %s: %s\n", argv[0], strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (strcmp(argv[2], "-p") == 0)
  {
    if (argc != 4)
    {
      fprintf(stderr, "PID required for -p\n");
      exit(EXIT_FAILURE);
    }

    errno = 0;
    char* endptr;
    state->gogoFD = -1;
    state->pid = strtol(argv[3], &endptr, 10);
    if (errno != 0 || *endptr != 0)
    {
      fprintf(stderr, "Bad PID '%s' or process doesn't exist: %s\n", argv[3], strerror(errno));
      exit(EXIT_FAILURE);
    }
    else
    {
      fprintf(stdout, "Going to profile process with PID %lld\n", (long long)state->pid);
      collectExistingMappings(state);
    }
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

    state->pid = fork();
    if (state->pid == -1)
    {
      perror("Can't fork");
      exit(EXIT_FAILURE);
    }

    if (state->pid == 0)
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
        execvp(argv[2], argv + 2);
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

      fprintf(stdout, "Going to profile process with PID %lld:", (long long)state->pid);
      for (int i = 2; i < argc; i++)
        fprintf(stdout, " %s", argv[i]);
      fputc('\n', stdout);
    }
  }
}

static int createPerfEvent(const struct PGCollectState* state)
{
  struct perf_event_attr pe_attr;
  memset(&pe_attr, 0, sizeof(struct perf_event_attr));

  pe_attr.type = PERF_TYPE_HARDWARE;
//  pe_attr.type = PERF_TYPE_SOFTWARE;
  pe_attr.size = sizeof(struct perf_event_attr);
  pe_attr.config = PERF_COUNT_HW_CPU_CYCLES;
//  pe_attr.config = PERF_COUNT_SW_CPU_CLOCK;
  pe_attr.sample_freq = 4000;
  pe_attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR |
      PERF_SAMPLE_CALLCHAIN;
  pe_attr.disabled = 1;
//  pe_attr.inherit = 0;
  pe_attr.exclude_kernel = 1;
  pe_attr.exclude_hv = 1;
  pe_attr.mmap = 1;
//  pe_attr.comm = 1;
  pe_attr.freq = 1;
  // watermark = 0
//  pe_attr.precise_ip = 2;
//  pe_attr.sample_id_all = 1;
//  pe_attr.exclude_host = 1;
//  pe_attr.exclude_guest = 1;

  // Wake for every single event
  pe_attr.wakeup_events = 5;

  int fd = perf_event_open(&pe_attr, state->pid, -1, -1, 0);
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

static void enablePerfEvent(int perfEventFD)
{
  ioctl(perfEventFD, PERF_EVENT_IOC_ENABLE, 0);
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

static __u64 processEvents(struct PerfMmapArea* area, const struct PGCollectState* state)
{
  // Read head
  __u64 head = area->header->data_head;
  rmb();

  if (area->prev == head)
    return 0;

  __u64 eventCount = 0;
  while (area->prev != head)
  {
    struct perf_event_header* eventHeader = (struct perf_event_header*)&(area->data[area->prev & area->mask]);

    if (eventHeader->type == PERF_RECORD_MMAP || eventHeader->type == PERF_RECORD_SAMPLE)
    {
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

    eventCount++;
    // Set tail
    area->header->data_tail = head;
  }

  return eventCount;
}

int main(int argc, char** argv)
{
  struct PGCollectState state;
  prepareState(&state, argc, argv);

  int perfEventFD = createPerfEvent(&state);
  struct PerfMmapArea perfEventArea;
  mmapPerfEvent(&perfEventArea, perfEventFD, &state);

  struct pollfd pollData;
  fillPollData(&pollData, perfEventFD);

  enablePerfEvent(perfEventFD);

  setupSignalHandlers(signalHandler);

  if (state.gogoFD != -1)
    pingProfiledProcess(state.gogoFD);

  while (1)
  {
    state.eventCount += processEvents(&perfEventArea, &state);

    if (stopCollecting)
      break;

    if (poll(&pollData, 1, -1) == -1 && errno != EINTR)
    {
      perror("Poll error");
      stopCollecting = 1;
    }
  }

  setupSignalHandlers(SIG_DFL);
  // Stop child
  if (state.gogoFD != -1)
    kill(state.pid, SIGTERM);

  puts("Collection stopped.");
  fclose(state.output);
  fprintf(stdout, "%lld events written\n", state.eventCount);
}
