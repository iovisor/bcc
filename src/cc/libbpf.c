/* eBPF mini library */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <linux/perf_event.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "libbpf.h"

static __u64 ptr_to_u64(void *ptr)
{
  return (__u64) (unsigned long) ptr;
}

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries)
{
  union bpf_attr attr = {
    .map_type = map_type,
    .key_size = key_size,
    .value_size = value_size,
    .max_entries = max_entries
  };

  return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .value = ptr_to_u64(value),
    .flags = flags,
  };

  return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, void *key, void *value)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .value = ptr_to_u64(value),
  };

  return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(int fd, void *key)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
  };

  return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .next_key = ptr_to_u64(next_key),
  };

  return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

#define ROUND_UP(x, n) (((x) + (n) - 1u) & ~((n) - 1u))

char bpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned kern_version)
{
  union bpf_attr attr = {
    .prog_type = prog_type,
    .insns = ptr_to_u64((void *) insns),
    .insn_cnt = prog_len / sizeof(struct bpf_insn),
    .license = ptr_to_u64((void *) license),
    .log_buf = ptr_to_u64(bpf_log_buf),
    .log_size = LOG_BUF_SIZE,
    .log_level = 1,
  };

  attr.kern_version = kern_version;
  bpf_log_buf[0] = 0;

  int ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  if (ret < 0) {
    fprintf(stderr, "bpf: %s\n%s\n", strerror(errno), bpf_log_buf);
  }
  return ret;
}

int bpf_open_raw_sock(const char *name)
{
  struct sockaddr_ll sll;
  int sock;

  sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (sock < 0) {
    printf("cannot create raw socket\n");
    return -1;
  }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_nametoindex(name);
  sll.sll_protocol = htons(ETH_P_ALL);
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    printf("bind to %s: %s\n", name, strerror(errno));
    close(sock);
    return -1;
  }

  return sock;
}

int bpf_attach_socket(int sock, int prog) {
  return setsockopt(sock, SOL_SOCKET, 50 /*SO_ATTACH_BPF*/, &prog, sizeof(prog));
}

static int bpf_attach_tracing_event(int progfd, const char *event_path, pid_t pid, int cpu, int group_fd)
{
  int efd = -1, rc = -1, pfd = -1;
  ssize_t bytes = -1;
  char buf[256];
  struct perf_event_attr attr = {};

  snprintf(buf, sizeof(buf), "%s/id", event_path);
  efd = open(buf, O_RDONLY, 0);
  if (efd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto cleanup;
  }

  bytes = read(efd, buf, sizeof(buf));
  if (bytes <= 0 || bytes >= sizeof(buf)) {
    fprintf(stderr, "read(%s): %s\n", buf, strerror(errno));
    goto cleanup;
  }
  buf[bytes] = '\0';
  attr.config = strtol(buf, NULL, 0);
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, group_fd, PERF_FLAG_FD_CLOEXEC);
  if (pfd < 0) {
    perror("perf_event_open");
    goto cleanup;
  }
  if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
    goto cleanup;
  }
  if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    goto cleanup;
  }

  rc = pfd;
  pfd = -1;

cleanup:
  if (efd >= 0)
    close(efd);
  if (pfd >= 0)
    close(pfd);

  return rc;
}

int bpf_attach_kprobe(int progfd, const char *event,
                      const char *event_desc, pid_t pid,
                      int cpu, int group_fd) {
  int rc = -1, kfd = -1;
  char buf[256];

  kfd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    perror("open(kprobe_events)");
    goto cleanup;
  }

  if (write(kfd, event_desc, strlen(event_desc)) < 0) {
    perror("write(kprobe_events)");
    goto cleanup;
  }

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/kprobes/%s", event);
  rc = bpf_attach_tracing_event(progfd, buf, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/);

cleanup:
  if (kfd >= 0)
    close(kfd);

  return rc;
}

