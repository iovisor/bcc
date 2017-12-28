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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_packet.h>
#include <linux/perf_event.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_alg.h>

#include "libbpf.h"
#include "perf_reader.h"

// TODO: Remove this when CentOS 6 support is not needed anymore
#include "setns.h"

// TODO: remove these defines when linux-libc-dev exports them properly

#ifndef __NR_bpf
#if defined(__powerpc64__)
#define __NR_bpf 361
#elif defined(__s390x__)
#define __NR_bpf 351
#elif defined(__aarch64__)
#define __NR_bpf 280
#else
#define __NR_bpf 321
#endif
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

// TODO: Remove this when CentOS 6 support is not needed anymore
#ifndef AF_ALG
#define AF_ALG 38
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

static int probe_perf_reader_page_cnt = 8;

static uint64_t ptr_to_u64(void *ptr)
{
  return (uint64_t) (unsigned long) ptr;
}

int bpf_create_map(enum bpf_map_type map_type, const char *name,
                   int key_size, int value_size,
                   int max_entries, int map_flags)
{
  size_t name_len = name ? strlen(name) : 0;
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_type = map_type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;
  memcpy(attr.map_name, name, min(name_len, BPF_OBJ_NAME_LEN - 1));

  int ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));

  if (ret < 0 && name_len && (errno == E2BIG || errno == EINVAL)) {
    memset(attr.map_name, 0, BPF_OBJ_NAME_LEN);
    ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
  }

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

int bpf_get_first_key(int fd, void *key, size_t key_size)
{
  union bpf_attr attr;
  int i, res;

  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = 0;
  attr.next_key = ptr_to_u64(key);

  // 4.12 and above kernel supports passing NULL to BPF_MAP_GET_NEXT_KEY
  // to get first key of the map. For older kernels, the call will fail.
  res = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
  if (res < 0 && errno == EFAULT) {
    // Fall back to try to find a non-existing key.
    static unsigned char try_values[3] = {0, 0xff, 0x55};
    attr.key = ptr_to_u64(key);
    for (i = 0; i < 3; i++) {
      memset(key, try_values[i], key_size);
      // We want to check the existence of the key but we don't know the size
      // of map's value. So we pass an invalid pointer for value, expect
      // the call to fail and check if the error is ENOENT indicating the
      // key doesn't exist. If we use NULL for the invalid pointer, it might
      // trigger a page fault in kernel and affect performance. Hence we use
      // ~0 which will fail and return fast.
      // This should fail since we pass an invalid pointer for value.
      if (bpf_lookup_elem(fd, key, (void *)~0) >= 0)
        return -1;
      // This means the key doesn't exist.
      if (errno == ENOENT)
        return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
    }
    return -1;
  } else {
    return res;
  }
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

static void bpf_print_hints(int ret, char *log)
{
  if (ret < 0)
    fprintf(stderr, "bpf: Failed to load program: %s\n", strerror(errno));
  if (log == NULL)
    return;
  else
    fprintf(stderr, "%s\n", log);

  if (ret >= 0)
    return;

  // The following error strings will need maintenance to match LLVM.

  // stack busting
  if (strstr(log, "invalid stack off=-") != NULL) {
    fprintf(stderr, "HINT: Looks like you exceeded the BPF stack limit. "
      "This can happen if you allocate too much local variable storage. "
      "For example, if you allocated a 1 Kbyte struct (maybe for "
      "BPF_PERF_OUTPUT), busting a max stack of 512 bytes.\n\n");
  }

  // didn't check NULL on map lookup
  if (strstr(log, "invalid mem access 'map_value_or_null'") != NULL) {
    fprintf(stderr, "HINT: The 'map_value_or_null' error can happen if "
      "you dereference a pointer value from a map lookup without first "
      "checking if that pointer is NULL.\n\n");
  }

  // lacking a bpf_probe_read
  if (strstr(log, "invalid mem access 'inv'") != NULL) {
    fprintf(stderr, "HINT: The invalid mem access 'inv' error can happen "
      "if you try to dereference memory without first using "
      "bpf_probe_read() to copy it to the BPF stack. Sometimes the "
      "bpf_probe_read is automatic by the bcc rewriter, other times "
      "you'll need to be explicit.\n\n");
  }
}
#define ROUND_UP(x, n) (((x) + (n) - 1u) & ~((n) - 1u))

int bpf_obj_get_info(int prog_map_fd, void *info, uint32_t *info_len)
{
  union bpf_attr attr;
  int err;

  memset(&attr, 0, sizeof(attr));
  attr.info.bpf_fd = prog_map_fd;
  attr.info.info_len = *info_len;
  attr.info.info = ptr_to_u64(info);

  err = syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
  if (!err)
          *info_len = attr.info.info_len;

  return err;
}

int bpf_prog_compute_tag(const struct bpf_insn *insns, int prog_len,
                         unsigned long long *ptag)
{
  struct sockaddr_alg alg = {
    .salg_family    = AF_ALG,
    .salg_type      = "hash",
    .salg_name      = "sha1",
  };
  int shafd = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (shafd < 0) {
    fprintf(stderr, "sha1 socket not available %s\n", strerror(errno));
    return -1;
  }
  int ret = bind(shafd, (struct sockaddr *)&alg, sizeof(alg));
  if (ret < 0) {
    fprintf(stderr, "sha1 bind fail %s\n", strerror(errno));
    close(shafd);
    return ret;
  }
  int shafd2 = accept(shafd, NULL, 0);
  if (shafd2 < 0) {
    fprintf(stderr, "sha1 accept fail %s\n", strerror(errno));
    close(shafd);
    return -1;
  }
  struct bpf_insn prog[prog_len / 8];
  bool map_ld_seen = false;
  int i;
  for (i = 0; i < prog_len / 8; i++) {
    prog[i] = insns[i];
    if (insns[i].code == (BPF_LD | BPF_DW | BPF_IMM) &&
        insns[i].src_reg == BPF_PSEUDO_MAP_FD &&
        !map_ld_seen) {
      prog[i].imm = 0;
      map_ld_seen = true;
    } else if (insns[i].code == 0 && map_ld_seen) {
      prog[i].imm = 0;
      map_ld_seen = false;
    } else {
      map_ld_seen = false;
    }
  }
  ret = write(shafd2, prog, prog_len);
  if (ret != prog_len) {
    fprintf(stderr, "sha1 write fail %s\n", strerror(errno));
    close(shafd2);
    close(shafd);
    return -1;
  }

  union {
	  unsigned char sha[20];
	  unsigned long long tag;
  } u = {};
  ret = read(shafd2, u.sha, 20);
  if (ret != 20) {
    fprintf(stderr, "sha1 read fail %s\n", strerror(errno));
    close(shafd2);
    close(shafd);
    return -1;
  }
  *ptag = __builtin_bswap64(u.tag);
  return 0;
}

int bpf_prog_get_tag(int fd, unsigned long long *ptag)
{
  char fmt[64];
  snprintf(fmt, sizeof(fmt), "/proc/self/fdinfo/%d", fd);
  FILE * f = fopen(fmt, "r");
  if (!f) {
/*    fprintf(stderr, "failed to open fdinfo %s\n", strerror(errno));*/
    return -1;
  }
  fgets(fmt, sizeof(fmt), f); // pos
  fgets(fmt, sizeof(fmt), f); // flags
  fgets(fmt, sizeof(fmt), f); // mnt_id
  fgets(fmt, sizeof(fmt), f); // prog_type
  fgets(fmt, sizeof(fmt), f); // prog_jited
  fgets(fmt, sizeof(fmt), f); // prog_tag
  fclose(f);
  char *p = strchr(fmt, ':');
  if (!p) {
/*    fprintf(stderr, "broken fdinfo %s\n", fmt);*/
    return -2;
  }
  unsigned long long tag = 0;
  sscanf(p + 1, "%llx", &tag);
  *ptag = tag;
  return 0;
}

int bpf_prog_load(enum bpf_prog_type prog_type, const char *name,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned kern_version,
                  int log_level, char *log_buf, unsigned log_buf_size)
{
  size_t name_len = name ? strlen(name) : 0;
  union bpf_attr attr;
  char *tmp_log_buf = NULL;
  unsigned tmp_log_buf_size = 0;
  int ret = 0;

  memset(&attr, 0, sizeof(attr));

  attr.prog_type = prog_type;
  attr.kern_version = kern_version;
  attr.license = ptr_to_u64((void *)license);

  attr.insns = ptr_to_u64((void *)insns);
  attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
  if (attr.insn_cnt > BPF_MAXINSNS) {
    errno = EINVAL;
    fprintf(stderr,
            "bpf: %s. Program too large (%u insns), at most %d insns\n\n",
            strerror(errno), attr.insn_cnt, BPF_MAXINSNS);
    return -1;
  }

  attr.log_level = log_level;
  if (attr.log_level > 0) {
    if (log_buf_size > 0) {
      // Use user-provided log buffer if availiable.
      log_buf[0] = 0;
      attr.log_buf = ptr_to_u64(log_buf);
      attr.log_size = log_buf_size;
    } else {
      // Create and use temporary log buffer if user didn't provide one.
      tmp_log_buf_size = LOG_BUF_SIZE;
      tmp_log_buf = malloc(tmp_log_buf_size);
      if (!tmp_log_buf) {
        fprintf(stderr, "bpf: Failed to allocate temporary log buffer: %s\n\n",
                strerror(errno));
        attr.log_level = 0;
      } else {
        tmp_log_buf[0] = 0;
        attr.log_buf = ptr_to_u64(tmp_log_buf);
        attr.log_size = tmp_log_buf_size;
      }
    }
  }

  memcpy(attr.prog_name, name, min(name_len, BPF_OBJ_NAME_LEN - 1));

  ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  // BPF object name is not supported on older Kernels.
  // If we failed due to this, clear the name and try again.
  if (ret < 0 && name_len && (errno == E2BIG || errno == EINVAL)) {
    memset(attr.prog_name, 0, BPF_OBJ_NAME_LEN);
    ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  }

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

  // The load has failed. Handle log message.
  if (ret < 0) {
    // User has provided a log buffer.
    if (log_buf_size) {
      // If logging is not already enabled, enable it and do the syscall again.
      if (attr.log_level == 0) {
        attr.log_level = 1;
        attr.log_buf = ptr_to_u64(log_buf);
        attr.log_size = log_buf_size;
        ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
      }
      // Print the log message and return.
      bpf_print_hints(ret, log_buf);
      if (errno == ENOSPC)
        fprintf(stderr, "bpf: log_buf size may be insufficient\n");
      goto return_result;
    }

    // User did not provide log buffer. We will try to increase size of
    // our temporary log buffer to get full error message.
    if (tmp_log_buf)
      free(tmp_log_buf);
    tmp_log_buf_size = LOG_BUF_SIZE;
    if (attr.log_level == 0)
      attr.log_level = 1;
    for (;;) {
      tmp_log_buf = malloc(tmp_log_buf_size);
      if (!tmp_log_buf) {
        fprintf(stderr, "bpf: Failed to allocate temporary log buffer: %s\n\n",
                strerror(errno));
        goto return_result;
      }
      tmp_log_buf[0] = 0;
      attr.log_buf = ptr_to_u64(tmp_log_buf);
      attr.log_size = tmp_log_buf_size;

      ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
      if (ret < 0 && errno == ENOSPC) {
        // Temporary buffer size is not enough. Double it and try again.
        free(tmp_log_buf);
        tmp_log_buf = NULL;
        tmp_log_buf_size <<= 1;
      } else {
        break;
      }
    }
  }

  // Check if we should print the log message if log_level is not 0,
  // either specified by user or set due to error.
  if (attr.log_level > 0) {
    // Don't print if user enabled logging and provided log buffer,
    // but there is no error.
    if (log_buf && ret < 0)
      bpf_print_hints(ret, log_buf);
    else if (tmp_log_buf)
      bpf_print_hints(ret, tmp_log_buf);
  }

return_result:
  if (tmp_log_buf)
    free(tmp_log_buf);
  return ret;
}

int bpf_open_raw_sock(const char *name)
{
  struct sockaddr_ll sll;
  int sock;

  sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (sock < 0) {
    fprintf(stderr, "cannot create raw socket\n");
    return -1;
  }

  /* Do not bind on empty interface names */
  if (!name || *name == '\0')
    return sock;

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_nametoindex(name);
  if (sll.sll_ifindex == 0) {
    fprintf(stderr, "bpf: Resolving device name to index: %s\n", strerror(errno));
    close(sock);
    return -1;
  }
  sll.sll_protocol = htons(ETH_P_ALL);
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    fprintf(stderr, "bind to %s: %s\n", name, strerror(errno));
    close(sock);
    return -1;
  }

  return sock;
}

int bpf_attach_socket(int sock, int prog) {
  return setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog, sizeof(prog));
}

static int bpf_attach_tracing_event(int progfd, const char *event_path,
                                    struct perf_reader *reader, int pid) {
  int efd, pfd, cpu = 0;
  ssize_t bytes;
  char buf[256];
  struct perf_event_attr attr = {};

  snprintf(buf, sizeof(buf), "%s/id", event_path);
  efd = open(buf, O_RDONLY, 0);
  if (efd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    return -1;
  }

  bytes = read(efd, buf, sizeof(buf));
  if (bytes <= 0 || bytes >= sizeof(buf)) {
    fprintf(stderr, "read(%s): %s\n", buf, strerror(errno));
    close(efd);
    return -1;
  }
  close(efd);
  buf[bytes] = '\0';
  attr.config = strtol(buf, NULL, 0);
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  // PID filter is only possible for uprobe events.
  if (pid < 0)
    pid = -1;
  // perf_event_open API doesn't allow both pid and cpu to be -1.
  // So only set it to -1 when PID is not -1.
  // Tracing events do not do CPU filtering in any cases.
  if (pid != -1)
    cpu = -1;
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
  if (pfd < 0) {
    fprintf(stderr, "perf_event_open(%s/id): %s\n", event_path, strerror(errno));
    return -1;
  }
  perf_reader_set_fd(reader, pfd);

  if (perf_reader_mmap(reader, attr.type, attr.sample_type) < 0)
    return -1;

  if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
    return -1;
  }
  if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    return -1;
  }

  return 0;
}

void *bpf_attach_kprobe(int progfd, enum bpf_probe_attach_type attach_type,
                        const char *ev_name, const char *fn_name,
                        perf_reader_cb cb, void *cb_cookie)
{
  int kfd;
  char buf[256];
  char event_alias[128];
  struct perf_reader *reader = NULL;
  static char *event_type = "kprobe";

  reader = perf_reader_new(cb, NULL, NULL, cb_cookie, probe_perf_reader_page_cnt);
  if (!reader)
    goto error;

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/%s_events", event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  snprintf(event_alias, sizeof(event_alias), "%s_bcc_%d", ev_name, getpid());
  snprintf(buf, sizeof(buf), "%c:%ss/%s %s", attach_type==BPF_PROBE_ENTRY ? 'p' : 'r',
			event_type, event_alias, fn_name);
  if (write(kfd, buf, strlen(buf)) < 0) {
    if (errno == EINVAL)
      fprintf(stderr, "check dmesg output for possible cause\n");
    close(kfd);
    goto error;
  }
  close(kfd);

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%ss/%s", event_type, event_alias);
  if (bpf_attach_tracing_event(progfd, buf, reader, -1 /* PID */) < 0)
    goto error;

  return reader;

error:
  perf_reader_free(reader);
  return NULL;

}

static int enter_mount_ns(int pid) {
  struct stat self_stat, target_stat;
  int self_fd = -1, target_fd = -1;
  char buf[64];

  if (pid < 0)
    return -1;

  if ((size_t)snprintf(buf, sizeof(buf), "/proc/%d/ns/mnt", pid) >= sizeof(buf))
    return -1;

  self_fd = open("/proc/self/ns/mnt", O_RDONLY);
  if (self_fd < 0) {
    perror("open(/proc/self/ns/mnt)");
    return -1;
  }

  target_fd = open(buf, O_RDONLY);
  if (target_fd < 0) {
    perror("open(/proc/<pid>/ns/mnt)");
    goto error;
  }

  if (fstat(self_fd, &self_stat)) {
    perror("fstat(self_fd)");
    goto error;
  }

  if (fstat(target_fd, &target_stat)) {
    perror("fstat(target_fd)");
    goto error;
  }

  // both target and current ns are same, avoid setns and close all fds
  if (self_stat.st_ino == target_stat.st_ino)
    goto error;

  if (setns(target_fd, CLONE_NEWNS)) {
    perror("setns(target)");
    goto error;
  }

  close(target_fd);
  return self_fd;

error:
  if (self_fd >= 0)
    close(self_fd);
  if (target_fd >= 0)
    close(target_fd);
  return -1;
}

static void exit_mount_ns(int fd) {
  if (fd < 0)
    return;

  if (setns(fd, CLONE_NEWNS))
    perror("setns");
}

void *bpf_attach_uprobe(int progfd, enum bpf_probe_attach_type attach_type,
                        const char *ev_name, const char *binary_path,
                        uint64_t offset, pid_t pid, perf_reader_cb cb,
                        void *cb_cookie)
{
  char buf[PATH_MAX];
  char event_alias[PATH_MAX];
  struct perf_reader *reader = NULL;
  static char *event_type = "uprobe";
  int res, kfd = -1, ns_fd = -1;

  reader = perf_reader_new(cb, NULL, NULL, cb_cookie, probe_perf_reader_page_cnt);
  if (!reader)
    goto error;

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/%s_events", event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  res = snprintf(event_alias, sizeof(event_alias), "%s_bcc_%d", ev_name, getpid());
  if (res < 0 || res >= sizeof(event_alias)) {
    fprintf(stderr, "Event name (%s) is too long for buffer\n", ev_name);
    goto error;
  }
  res = snprintf(buf, sizeof(buf), "%c:%ss/%s %s:0x%lx", attach_type==BPF_PROBE_ENTRY ? 'p' : 'r',
			event_type, event_alias, binary_path, offset);
  if (res < 0 || res >= sizeof(buf)) {
    fprintf(stderr, "Event alias (%s) too long for buffer\n", event_alias);
    goto error;
  }

  ns_fd = enter_mount_ns(pid);
  if (write(kfd, buf, strlen(buf)) < 0) {
    if (errno == EINVAL)
      fprintf(stderr, "check dmesg output for possible cause\n");
    goto error;
  }
  close(kfd);
  exit_mount_ns(ns_fd);
  ns_fd = -1;

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%ss/%s", event_type, event_alias);
  if (bpf_attach_tracing_event(progfd, buf, reader, pid) < 0)
    goto error;

  return reader;

error:
  if (kfd >= 0)
    close(kfd);
  exit_mount_ns(ns_fd);
  perf_reader_free(reader);
  return NULL;
}

static int bpf_detach_probe(const char *ev_name, const char *event_type)
{
  int kfd, res;
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/%s_events", event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  res = snprintf(buf, sizeof(buf), "-:%ss/%s_bcc_%d", event_type, ev_name, getpid());
  if (res < 0 || res >= sizeof(buf)) {
    fprintf(stderr, "snprintf(%s): %d\n", ev_name, res);
    goto error;
  }
  if (write(kfd, buf, strlen(buf)) < 0) {
    fprintf(stderr, "write(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  close(kfd);
  return 0;

error:
  if (kfd >= 0)
    close(kfd);
  return -1;
}

int bpf_detach_kprobe(const char *ev_name)
{
  return bpf_detach_probe(ev_name, "kprobe");
}

int bpf_detach_uprobe(const char *ev_name)
{
  return bpf_detach_probe(ev_name, "uprobe");
}


void *bpf_attach_tracepoint(int progfd, const char *tp_category,
                            const char *tp_name, perf_reader_cb cb,
                            void *cb_cookie) {
  char buf[256];
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(cb, NULL, NULL, cb_cookie, probe_perf_reader_page_cnt);
  if (!reader)
    goto error;

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%s/%s",
           tp_category, tp_name);
  if (bpf_attach_tracing_event(progfd, buf, reader, -1 /* PID */) < 0)
    goto error;

  return reader;

error:
  perf_reader_free(reader);
  return NULL;
}

int bpf_detach_tracepoint(const char *tp_category, const char *tp_name) {
  // Right now, there is nothing to do, but it's a good idea to encourage
  // callers to detach anything they attach.
  return 0;
}

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb,
                            perf_reader_lost_cb lost_cb, void *cb_cookie,
                            int pid, int cpu, int page_cnt) {
  int pfd;
  struct perf_event_attr attr = {};
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(NULL, raw_cb, lost_cb, cb_cookie, page_cnt);
  if (!reader)
    goto error;

  attr.config = 10;//PERF_COUNT_SW_BPF_OUTPUT;
  attr.type = PERF_TYPE_SOFTWARE;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (pfd < 0) {
    fprintf(stderr, "perf_event_open: %s\n", strerror(errno));
    fprintf(stderr, "   (check your kernel for PERF_COUNT_SW_BPF_OUTPUT support, 4.4 or newer)\n");
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
}

static int invalid_perf_config(uint32_t type, uint64_t config) {
  switch (type) {
  case PERF_TYPE_HARDWARE:
    if (config >= PERF_COUNT_HW_MAX) {
      fprintf(stderr, "HARDWARE perf event config out of range\n");
      goto is_invalid;
    }
    return 0;
  case PERF_TYPE_SOFTWARE:
    if (config >= PERF_COUNT_SW_MAX) {
      fprintf(stderr, "SOFTWARE perf event config out of range\n");
      goto is_invalid;
    } else if (config == 10 /* PERF_COUNT_SW_BPF_OUTPUT */) {
      fprintf(stderr, "Unable to open or attach perf event for BPF_OUTPUT\n");
      goto is_invalid;
    }
    return 0;
  case PERF_TYPE_HW_CACHE:
    if (((config >> 16) >= PERF_COUNT_HW_CACHE_RESULT_MAX) ||
        (((config >> 8) & 0xff) >= PERF_COUNT_HW_CACHE_OP_MAX) ||
        ((config & 0xff) >= PERF_COUNT_HW_CACHE_MAX)) {
      fprintf(stderr, "HW_CACHE perf event config out of range\n");
      goto is_invalid;
    }
    return 0;
  case PERF_TYPE_TRACEPOINT:
  case PERF_TYPE_BREAKPOINT:
    fprintf(stderr,
            "Unable to open or attach TRACEPOINT or BREAKPOINT events\n");
    goto is_invalid;
  default:
    return 0;
  }
is_invalid:
  fprintf(stderr, "Invalid perf event type %" PRIu32 " config %" PRIu64 "\n",
          type, config);
  return 1;
}

int bpf_open_perf_event(uint32_t type, uint64_t config, int pid, int cpu) {
  int fd;
  struct perf_event_attr attr = {};

  if (invalid_perf_config(type, config)) {
    return -1;
  }

  attr.sample_period = LONG_MAX;
  attr.type = type;
  attr.config = config;

  fd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "perf_event_open: %s\n", strerror(errno));
    return -1;
  }

  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    close(fd);
    return -1;
  }

  return fd;
}

int bpf_attach_xdp(const char *dev_name, int progfd, uint32_t flags) {
    struct sockaddr_nl sa;
    int sock, seq = 0, len, ret = -1;
    char buf[4096];
    struct nlattr *nla, *nla_xdp;
    struct {
        struct nlmsghdr  nh;
        struct ifinfomsg ifinfo;
        char             attrbuf[64];
    } req;
    struct nlmsghdr *nh;
    struct nlmsgerr *err;
    socklen_t addrlen;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        fprintf(stderr, "bpf: opening a netlink socket: %s\n", strerror(errno));
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "bpf: bind to netlink: %s\n", strerror(errno));
        goto cleanup;
    }

    addrlen = sizeof(sa);
    if (getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0) {
        fprintf(stderr, "bpf: get sock name of netlink: %s\n", strerror(errno));
        goto cleanup;
    }

    if (addrlen != sizeof(sa)) {
        fprintf(stderr, "bpf: wrong netlink address length: %d\n", addrlen);
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_type = RTM_SETLINK;
    req.nh.nlmsg_pid = 0;
    req.nh.nlmsg_seq = ++seq;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index = if_nametoindex(dev_name);
    if (req.ifinfo.ifi_index == 0) {
        fprintf(stderr, "bpf: Resolving device name to index: %s\n", strerror(errno));
        goto cleanup;
    }

    nla = (struct nlattr *)(((char *)&req)
                            + NLMSG_ALIGN(req.nh.nlmsg_len));
    nla->nla_type = NLA_F_NESTED | 43/*IFLA_XDP*/;

    nla_xdp = (struct nlattr *)((char *)nla + NLA_HDRLEN);
    nla->nla_len = NLA_HDRLEN;

    // we specify the FD passed over by the user
    nla_xdp->nla_type = 1/*IFLA_XDP_FD*/;
    nla_xdp->nla_len = NLA_HDRLEN + sizeof(progfd);
    memcpy((char *)nla_xdp + NLA_HDRLEN, &progfd, sizeof(progfd));
    nla->nla_len += nla_xdp->nla_len;

    // parse flags as passed by the user
    if (flags) {
        nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
        nla_xdp->nla_type = 3/*IFLA_XDP_FLAGS*/;
        nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
        memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
        nla->nla_len += nla_xdp->nla_len;
    }

    req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
        fprintf(stderr, "bpf: send to netlink: %s\n", strerror(errno));
        goto cleanup;
    }

    len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) {
        fprintf(stderr, "bpf: recv from netlink: %s\n", strerror(errno));
        goto cleanup;
    }

    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
         nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_pid != sa.nl_pid) {
            fprintf(stderr, "bpf: Wrong pid %u, expected %u\n",
                   nh->nlmsg_pid, sa.nl_pid);
            errno = EBADMSG;
            goto cleanup;
        }
        if (nh->nlmsg_seq != seq) {
            fprintf(stderr, "bpf: Wrong seq %d, expected %d\n",
                   nh->nlmsg_seq, seq);
            errno = EBADMSG;
            goto cleanup;
        }
        switch (nh->nlmsg_type) {
            case NLMSG_ERROR:
                err = (struct nlmsgerr *)NLMSG_DATA(nh);
                if (!err->error)
                    continue;
                fprintf(stderr, "bpf: nlmsg error %s\n", strerror(-err->error));
                errno = -err->error;
                goto cleanup;
            case NLMSG_DONE:
                break;
        }
    }

    ret = 0;

cleanup:
    close(sock);
    return ret;
}

int bpf_attach_perf_event(int progfd, uint32_t ev_type, uint32_t ev_config,
                          uint64_t sample_period, uint64_t sample_freq,
                          pid_t pid, int cpu, int group_fd) {
  if (invalid_perf_config(ev_type, ev_config)) {
    return -1;
  }
  if (!((sample_period > 0) ^ (sample_freq > 0))) {
    fprintf(
      stderr, "Exactly one of sample_period / sample_freq should be set\n"
    );
    return -1;
  }

  struct perf_event_attr attr = {};
  attr.type = ev_type;
  attr.config = ev_config;
  if (pid > 0)
    attr.inherit = 1;
  if (sample_freq > 0) {
    attr.freq = 1;
    attr.sample_freq = sample_freq;
  } else {
    attr.sample_period = sample_period;
  }

  int fd = syscall(
    __NR_perf_event_open, &attr, pid, cpu, group_fd, PERF_FLAG_FD_CLOEXEC
  );
  if (fd < 0) {
    perror("perf_event_open failed");
    return -1;
  }
  if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, progfd) != 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF) failed");
    close(fd);
    return -1;
  }
  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE) failed");
    close(fd);
    return -1;
  }

  return fd;
}

int bpf_close_perf_event_fd(int fd) {
  int res, error = 0;
  if (fd >= 0) {
    res = ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    if (res != 0) {
      perror("ioctl(PERF_EVENT_IOC_DISABLE) failed");
      error = res;
    }
    res = close(fd);
    if (res != 0) {
      perror("close perf event FD failed");
      error = (res && !error) ? res : error;
    }
  }
  return error;
}

int bpf_obj_pin(int fd, const char *pathname)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.pathname = ptr_to_u64((void *)pathname);
  attr.bpf_fd = fd;

  return syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}

int bpf_obj_get(const char *pathname)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.pathname = ptr_to_u64((void *)pathname);

  return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

int bpf_prog_get_next_id(uint32_t start_id, uint32_t *next_id)
{
  union bpf_attr attr;
  int err;

  memset(&attr, 0, sizeof(attr));
  attr.start_id = start_id;

  err = syscall(__NR_bpf, BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
  if (!err)
    *next_id = attr.next_id;

  return err;
}

int bpf_prog_get_fd_by_id(uint32_t id)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.prog_id = id;

  return syscall(__NR_bpf, BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
}

int bpf_map_get_fd_by_id(uint32_t id)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_id = id;

  return syscall(__NR_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}
