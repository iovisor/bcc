/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
#include <sys/resource.h>
#include <unistd.h>

#include "libbpf.h"
#include "perf_reader.h"

// TODO: remove these defines when linux-libc-dev exports them properly

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF 50
#endif

#ifndef PERF_EVENT_IOC_SET_BPF
#define PERF_EVENT_IOC_SET_BPF _IOW('$', 8, __u32)
#endif

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)
#endif

static __u64 ptr_to_u64(void *ptr)
{
  return (__u64) (unsigned long) ptr;
}

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_type = map_type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;

  int ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
  if (ret < 0 && errno == EPERM) {
    // see note below about the rationale for this retry

    struct rlimit rl = {};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
      rl.rlim_max = RLIM_INFINITY;
      rl.rlim_cur = rl.rlim_max;
      if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    }
  }
  return ret;
}

int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);
  attr.flags = flags;

  return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, void *key, void *value)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);

  return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(int fd, void *key)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);

  return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.next_key = ptr_to_u64(next_key);

  return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

#define ROUND_UP(x, n) (((x) + (n) - 1u) & ~((n) - 1u))

char bpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned kern_version,
                  char *log_buf, unsigned log_buf_size)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = prog_type;
  attr.insns = ptr_to_u64((void *) insns);
  attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
  attr.license = ptr_to_u64((void *) license);
  attr.log_buf = ptr_to_u64(log_buf);
  attr.log_size = log_buf_size;
  attr.log_level = log_buf ? 1 : 0;

  attr.kern_version = kern_version;
  if (log_buf)
    log_buf[0] = 0;

  int ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  if (ret < 0 && errno == EPERM) {
    // When EPERM is returned, two reasons are possible:
    //  1. user has no permissions for bpf()
    //  2. user has insufficent rlimit for locked memory
    // Unfortunately, there is no api to inspect the current usage of locked
    // mem for the user, so an accurate calculation of how much memory to lock
    // for this new program is difficult to calculate. As a hack, bump the limit
    // to unlimited. If program load fails again, return the error.

    struct rlimit rl = {};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
      rl.rlim_max = RLIM_INFINITY;
      rl.rlim_cur = rl.rlim_max;
      if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    }
  }

  if (ret < 0 && !log_buf) {
    // caller did not specify log_buf but failure should be printed,
    // so call recursively and print the result to stderr
    bpf_prog_load(prog_type, insns, prog_len, license, kern_version,
        bpf_log_buf, LOG_BUF_SIZE);
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
  return setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog, sizeof(prog));
}

static int bpf_attach_tracing_event(int progfd, const char *event_path,
    struct perf_reader *reader, int pid, int cpu, int group_fd) {
  int efd = -1, pfd;
  ssize_t bytes;
  char buf[256];
  struct perf_event_attr attr = {};

  snprintf(buf, sizeof(buf), "%s/id", event_path);
  efd = open(buf, O_RDONLY, 0);
  if (efd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  bytes = read(efd, buf, sizeof(buf));
  if (bytes <= 0 || bytes >= sizeof(buf)) {
    fprintf(stderr, "read(%s): %s\n", buf, strerror(errno));
    goto error;
  }
  buf[bytes] = '\0';
  attr.config = strtol(buf, NULL, 0);
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, group_fd, PERF_FLAG_FD_CLOEXEC);
  if (pfd < 0) {
    perror("perf_event_open");
    goto error;
  }
  perf_reader_set_fd(reader, pfd);

  if (perf_reader_mmap(reader, attr.type, attr.sample_type) < 0)
    goto error;

  if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
    goto error;
  }
  if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    goto error;
  }

  return 0;

error:
  if (efd >= 0)
    close(efd);

  return -1;
}

void * bpf_attach_kprobe(int progfd, const char *event,
                         const char *event_desc, pid_t pid,
                         int cpu, int group_fd, perf_reader_cb cb,
                         void *cb_cookie) {
  int kfd = -1;
  char buf[256];
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(cb, NULL, cb_cookie);
  if (!reader)
    goto error;

  kfd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    perror("open(kprobe_events)");
    goto error;
  }

  if (write(kfd, event_desc, strlen(event_desc)) < 0) {
    fprintf(stderr, "write of \"%s\" into kprobe_events failed: %s\n", event_desc, strerror(errno));
    if (errno == EINVAL)
      fprintf(stderr, "check dmesg output for possible cause\n");
    goto error;
  }

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/kprobes/%s", event);
  if (bpf_attach_tracing_event(progfd, buf, reader, pid, cpu, group_fd) < 0)
    goto error;

  return reader;

error:
  if (kfd >= 0)
    close(kfd);
  if (reader)
    perf_reader_free(reader);

  return NULL;
}

int bpf_detach_kprobe(const char *event_desc) {
  int kfd = -1;

  kfd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    perror("open(kprobe_events)");
    goto error;
  }

  if (write(kfd, event_desc, strlen(event_desc)) < 0) {
    perror("write(kprobe_events)");
    goto error;
  }

  return 0;

error:
  if (kfd >= 0)
    close(kfd);

  return -1;
}

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb, void *cb_cookie, int pid, int cpu) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
  int pfd;
  struct perf_event_attr attr = {};
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(NULL, raw_cb, cb_cookie);
  if (!reader)
    goto error;

  attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  attr.type = PERF_TYPE_SOFTWARE;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (pfd < 0) {
    perror("perf_event_open");
    goto error;
  }
  perf_reader_set_fd(reader, pfd);

  if (perf_reader_mmap(reader, attr.type, attr.sample_type) < 0)
    goto error;

  if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    goto error;
  }

  return reader;

error:
  if (reader)
    perf_reader_free(reader);

  return NULL;
#else
  fprintf(stderr, "PERF_COUNT_SW_BPF_OUTPUT feature unsupported\n");
  return NULL;
#endif
}
