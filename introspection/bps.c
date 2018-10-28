#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sysexits.h>

#include "libbpf.h"

// TODO: Remove this when CentOS 6 support is not needed anymore
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

static const char * const prog_type_strings[] = {
  [BPF_PROG_TYPE_UNSPEC] = "unspec",
  [BPF_PROG_TYPE_SOCKET_FILTER] = "socket filter",
  [BPF_PROG_TYPE_KPROBE] = "kprobe",
  [BPF_PROG_TYPE_SCHED_CLS] = "sched cls",
  [BPF_PROG_TYPE_SCHED_ACT] = "sched act",
  [BPF_PROG_TYPE_TRACEPOINT] = "tracepoint",
  [BPF_PROG_TYPE_XDP] = "xdp",
  [BPF_PROG_TYPE_PERF_EVENT] = "perf event",
  [BPF_PROG_TYPE_CGROUP_SKB] = "cgroup skb",
  [BPF_PROG_TYPE_CGROUP_SOCK] = "cgroup sock",
  [BPF_PROG_TYPE_LWT_IN] = "lwt in",
  [BPF_PROG_TYPE_LWT_OUT] = "lwt out",
  [BPF_PROG_TYPE_LWT_XMIT] = "lwt xmit",
  [BPF_PROG_TYPE_SOCK_OPS] = "sock ops",
  [BPF_PROG_TYPE_SK_SKB] = "sk skb",
  [BPF_PROG_TYPE_CGROUP_DEVICE] = "cgroup_device",
  [BPF_PROG_TYPE_SK_MSG] = "sk_msg",
  [BPF_PROG_TYPE_RAW_TRACEPOINT] = "raw_tracepoint",
  [BPF_PROG_TYPE_CGROUP_SOCK_ADDR] = "cgroup_sock_addr",
  [BPF_PROG_TYPE_LIRC_MODE2] = "lirc_mode2",
  [BPF_PROG_TYPE_SK_REUSEPORT] = "sk_reuseport",
  [BPF_PROG_TYPE_FLOW_DISSECTOR] = "flow_dissector",
};

static const char * const map_type_strings[] = {
  [BPF_MAP_TYPE_UNSPEC] = "unspec",
  [BPF_MAP_TYPE_HASH] = "hash",
  [BPF_MAP_TYPE_ARRAY] = "array",
  [BPF_MAP_TYPE_PROG_ARRAY] = "prog array",
  [BPF_MAP_TYPE_PERF_EVENT_ARRAY] = "perf-ev array",
  [BPF_MAP_TYPE_PERCPU_HASH] = "percpu hash",
  [BPF_MAP_TYPE_PERCPU_ARRAY] = "percpu array",
  [BPF_MAP_TYPE_STACK_TRACE] = "stack trace",
  [BPF_MAP_TYPE_CGROUP_ARRAY] = "cgroup array",
  [BPF_MAP_TYPE_LRU_HASH] = "lru hash",
  [BPF_MAP_TYPE_LRU_PERCPU_HASH] = "lru percpu hash",
  [BPF_MAP_TYPE_LPM_TRIE] = "lpm trie",
  [BPF_MAP_TYPE_ARRAY_OF_MAPS] = "array of maps",
  [BPF_MAP_TYPE_HASH_OF_MAPS] = "hash of maps",
  [BPF_MAP_TYPE_DEVMAP] = "devmap",
  [BPF_MAP_TYPE_SOCKMAP] = "sockmap",
  [BPF_MAP_TYPE_CPUMAP] = "cpumap",
  [BPF_MAP_TYPE_SOCKHASH] = "sockhash",
  [BPF_MAP_TYPE_CGROUP_STORAGE] = "cgroup_storage",
  [BPF_MAP_TYPE_REUSEPORT_SOCKARRAY] = "reuseport_sockarray",
  [BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE] = "precpu_cgroup_storage",
  [BPF_MAP_TYPE_QUEUE] = "queue",
  [BPF_MAP_TYPE_STACK] = "stack",
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define LAST_KNOWN_PROG_TYPE (ARRAY_SIZE(prog_type_strings) - 1)
#define LAST_KNOWN_MAP_TYPE (ARRAY_SIZE(map_type_strings) - 1)
#define min(x, y) ((x) < (y) ? (x) : (y))

static inline uint64_t ptr_to_u64(const void *ptr)
{
  return (uint64_t) (unsigned long) ptr;
}

static inline void * u64_to_ptr(uint64_t ptr)
{
  return (void *) (unsigned long ) ptr;
}

static int handle_get_next_errno(int eno)
{
  switch (eno) {
    case ENOENT:
      return 0;
    case EINVAL:
      fprintf(stderr, "Kernel does not support BPF introspection\n");
      return EX_UNAVAILABLE;
    case EPERM:
      fprintf(stderr,
              "Require CAP_SYS_ADMIN capability.  Please retry as root\n");
      return EX_NOPERM;
    default:
      fprintf(stderr, "%s\n", strerror(errno));
      return 1;
  }
}

static void print_prog_hdr(void)
{
  printf("%9s %-15s %8s %6s %-12s %-15s\n",
         "BID", "TYPE", "UID", "#MAPS", "LoadTime", "NAME");
}

static void print_prog_info(const struct bpf_prog_info *prog_info)
{
  struct timespec real_time_ts, boot_time_ts;
  time_t wallclock_load_time = 0;
  char unknown_prog_type[16];
  const char *prog_type;
  char load_time[16];
  struct tm load_tm;

  if (prog_info->type > LAST_KNOWN_PROG_TYPE) {
    snprintf(unknown_prog_type, sizeof(unknown_prog_type), "<%u>",
             prog_info->type);
    unknown_prog_type[sizeof(unknown_prog_type) - 1] = '\0';
    prog_type = unknown_prog_type;
  } else {
    prog_type = prog_type_strings[prog_info->type];
  }

  if (!clock_gettime(CLOCK_REALTIME, &real_time_ts) &&
      !clock_gettime(CLOCK_BOOTTIME, &boot_time_ts) &&
      real_time_ts.tv_sec >= boot_time_ts.tv_sec)
    wallclock_load_time =
      (real_time_ts.tv_sec - boot_time_ts.tv_sec) +
      prog_info->load_time / 1000000000;

  if (wallclock_load_time && localtime_r(&wallclock_load_time, &load_tm))
    strftime(load_time, sizeof(load_time), "%b%d/%H:%M", &load_tm);
  else
    snprintf(load_time, sizeof(load_time), "<%llu>",
             prog_info->load_time / 1000000000);
  load_time[sizeof(load_time) - 1] = '\0';

  if (prog_info->jited_prog_len)
    printf("%9u %-15s %8u %6u %-12s %-15s\n",
           prog_info->id, prog_type, prog_info->created_by_uid,
           prog_info->nr_map_ids, load_time, prog_info->name);
  else
    printf("%8u- %-15s %8u %6u %-12s %-15s\n",
           prog_info->id, prog_type, prog_info->created_by_uid,
           prog_info->nr_map_ids, load_time, prog_info->name);
}

static void print_map_hdr(void)
{
  printf("%8s %-15s %-10s %8s %8s %8s %-15s\n",
         "MID", "TYPE", "FLAGS", "KeySz", "ValueSz", "MaxEnts",
         "NAME");
}

static void print_map_info(const struct bpf_map_info *map_info)
{
  char unknown_map_type[16];
  const char *map_type;

  if (map_info->type > LAST_KNOWN_MAP_TYPE) {
    snprintf(unknown_map_type, sizeof(unknown_map_type),
             "<%u>", map_info->type);
    unknown_map_type[sizeof(unknown_map_type) - 1] = '\0';
    map_type = unknown_map_type;
  } else {
    map_type = map_type_strings[map_info->type];
  }

  printf("%8u %-15s 0x%-8x %8u %8u %8u %-15s\n",
         map_info->id, map_type, map_info->map_flags, map_info->key_size,
         map_info->value_size, map_info->max_entries,
         map_info->name);
}

static int print_one_prog(uint32_t prog_id)
{
  const uint32_t usual_nr_map_ids = 64;
  uint32_t nr_map_ids = usual_nr_map_ids;
  struct bpf_prog_info prog_info;
  uint32_t *map_ids =  NULL;
  uint32_t info_len;
  int ret = 0;
  int prog_fd;
  uint32_t i;

  prog_fd = bpf_prog_get_fd_by_id(prog_id);
  if (prog_fd == -1) {
    if (errno == ENOENT) {
      fprintf(stderr, "BID:%u not found\n", prog_id);
      return EX_DATAERR;
    } else {
      return handle_get_next_errno(errno);
    }
  }

  /* Retry at most one time for larger map_ids array */
  for (i = 0; i < 2; i++) {
    bzero(&prog_info, sizeof(prog_info));
    prog_info.map_ids = ptr_to_u64(realloc(map_ids,
                                           nr_map_ids * sizeof(*map_ids)));
    if (!prog_info.map_ids) {
      fprintf(stderr,
              "Cannot allocate memory for %u map_ids for BID:%u\n",
              nr_map_ids, prog_id);
      close(prog_fd);
      free(map_ids);
      return 1;
    }

    map_ids = u64_to_ptr(prog_info.map_ids);
    prog_info.nr_map_ids = nr_map_ids;
    info_len = sizeof(prog_info);
    ret = bpf_obj_get_info(prog_fd, &prog_info, &info_len);
    if (ret) {
      fprintf(stderr, "Cannot get info for BID:%u. %s(%d)\n",
              prog_id, strerror(errno), errno);
      close(prog_fd);
      free(map_ids);
      return ret;
    }

    if (prog_info.nr_map_ids <= nr_map_ids)
      break;

    nr_map_ids = prog_info.nr_map_ids;
  }
  close(prog_fd);

  print_prog_hdr();
  print_prog_info(&prog_info);
  printf("\n");

  /* Print all map_info used by the prog */
  print_map_hdr();
  nr_map_ids = min(prog_info.nr_map_ids, nr_map_ids);
  for (i = 0; i < nr_map_ids; i++) {
    struct bpf_map_info map_info = {};
    info_len = sizeof(map_info);
    int map_fd;

    map_fd = bpf_map_get_fd_by_id(map_ids[i]);
    if (map_fd == -1) {
      if (errno == -ENOENT)
        continue;

      fprintf(stderr,
              "Cannot get fd for map:%u. %s(%d)\n",
              map_ids[i], strerror(errno), errno);
      ret = map_fd;
      break;
    }

    ret = bpf_obj_get_info(map_fd, &map_info, &info_len);
    close(map_fd);
    if (ret) {
      fprintf(stderr, "Cannot get info for map:%u. %s(%d)\n",
              map_ids[i], strerror(errno), errno);
      break;
    }

    print_map_info(&map_info);
  }

  free(map_ids);
  return ret;
}

int print_all_progs(void)
{
  uint32_t next_id = 0;

  print_prog_hdr();

  while (!bpf_prog_get_next_id(next_id, &next_id)) {
    struct bpf_prog_info prog_info = {};
    uint32_t prog_info_len = sizeof(prog_info);
    int prog_fd;
    int ret;

    prog_fd = bpf_prog_get_fd_by_id(next_id);
    if (prog_fd < 0) {
      if (errno == ENOENT)
        continue;
      fprintf(stderr,
              "Cannot get fd for BID:%u. %s(%d)\n",
              next_id, strerror(errno), errno);
      return 1;
    }

    ret = bpf_obj_get_info(prog_fd, &prog_info, &prog_info_len);
    close(prog_fd);
    if (ret) {
      fprintf(stderr,
              "Cannot get bpf_prog_info for BID:%u. %s(%d)\n",
              next_id, strerror(errno), errno);
      return ret;
    }

    print_prog_info(&prog_info);
  }

  return handle_get_next_errno(errno);
}

void usage(void)
{
  printf("BPF Program Snapshot (bps):\n"
         "List of all BPF programs loaded into the system.\n\n");
  printf("Usage: bps [bpf-prog-id]\n");
  printf("    [bpf-prog-id] If specified, it shows the details info of the bpf-prog\n");
  printf("\n");
}

int main(int argc, char **argv)
{
  if (argc > 1) {
    if (!isdigit(*argv[1])) {
      usage();
      return EX_USAGE;
    }
    return print_one_prog((uint32_t)atoi(argv[1]));
  }

  return print_all_progs();
}
