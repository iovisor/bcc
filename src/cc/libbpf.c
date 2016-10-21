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
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <linux/perf_event.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/bpf_common.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdbool.h>

#include "libbpf.h"
#include "perf_reader.h"

// TODO: remove these defines when linux-libc-dev exports them properly

#ifndef __NR_bpf
#if defined(__powerpc64__)
#define __NR_bpf 361
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

int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned kern_version,
                  char *log_buf, unsigned log_buf_size)
{
  union bpf_attr attr;
  char *bpf_log_buffer = NULL;
  unsigned buffer_size = 0;
  int ret = 0;

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

  if (attr.insn_cnt > BPF_MAXINSNS) {
    ret = -1;
    errno = EINVAL;
    fprintf(stderr,
            "bpf: %s. Program too large (%d insns), at most %d insns\n\n",
            strerror(errno), attr.insn_cnt, BPF_MAXINSNS);
    return ret;
  }

  ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
   
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

    buffer_size = LOG_BUF_SIZE;
    // caller did not specify log_buf but failure should be printed,
    // so repeat the syscall and print the result to stderr
    for (;;) {
         bpf_log_buffer = malloc(buffer_size);
         if (!bpf_log_buffer) {
             fprintf(stderr,
                     "bpf: buffer log memory allocation failed for error %s\n\n",
                     strerror(errno));
             return ret;
         }

         attr.log_buf = ptr_to_u64(bpf_log_buffer);
         attr.log_size = buffer_size;
         attr.log_level = bpf_log_buffer ? 1 : 0;

         ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
         if (ret < 0 && errno == ENOSPC) {
             free(bpf_log_buffer);
             bpf_log_buffer = NULL;
             buffer_size <<= 1;
         } else {
             break;
         }
    }

    fprintf(stderr, "bpf: %s\n%s\n", strerror(errno), bpf_log_buffer);

    free(bpf_log_buffer); 
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
  int efd, pfd;
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
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, group_fd, PERF_FLAG_FD_CLOEXEC);
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

static void * bpf_attach_probe(int progfd, const char *event,
                               const char *event_desc, const char *event_type,
                               pid_t pid, int cpu, int group_fd,
                               perf_reader_cb cb, void *cb_cookie) {
  int kfd;
  char buf[256];
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(cb, NULL, cb_cookie);
  if (!reader)
    goto error;

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/%s_events", event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  if (write(kfd, event_desc, strlen(event_desc)) < 0) {
    fprintf(stderr, "write(%s, \"%s\") failed: %s\n", buf, event_desc, strerror(errno));
    if (errno == EINVAL)
      fprintf(stderr, "check dmesg output for possible cause\n");
    close(kfd);
    goto error;
  }
  close(kfd);

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%ss/%s", event_type, event);
  if (bpf_attach_tracing_event(progfd, buf, reader, pid, cpu, group_fd) < 0)
    goto error;

  return reader;

error:
  perf_reader_free(reader);
  return NULL;
}

void * bpf_attach_kprobe(int progfd, const char *event,
                        const char *event_desc,
                        pid_t pid, int cpu, int group_fd,
                        perf_reader_cb cb, void *cb_cookie) {
  return bpf_attach_probe(progfd, event, event_desc, "kprobe", pid, cpu, group_fd, cb, cb_cookie);
}

void * bpf_attach_uprobe(int progfd, const char *event,
                        const char *event_desc,
                        pid_t pid, int cpu, int group_fd,
                        perf_reader_cb cb, void *cb_cookie) {
  return bpf_attach_probe(progfd, event, event_desc, "uprobe", pid, cpu, group_fd, cb, cb_cookie);
}

static int bpf_detach_probe(const char *event_desc, const char *event_type) {
  int kfd;

  char buf[256];
  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/%s_events", event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    return -1;
  }

  if (write(kfd, event_desc, strlen(event_desc)) < 0) {
    fprintf(stderr, "write(%s): %s\n", buf, strerror(errno));
    close(kfd);
    return -1;
  }
  close(kfd);

  return 0;
}

int bpf_detach_kprobe(const char *event_desc) {
  return bpf_detach_probe(event_desc, "kprobe");
}

int bpf_detach_uprobe(const char *event_desc) {
  return bpf_detach_probe(event_desc, "uprobe");
}

void * bpf_attach_tracepoint(int progfd, const char *tp_category,
                             const char *tp_name, int pid, int cpu,
                             int group_fd, perf_reader_cb cb, void *cb_cookie) {
  char buf[256];
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(cb, NULL, cb_cookie);
  if (!reader)
    goto error;

  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%s/%s",
           tp_category, tp_name);
  if (bpf_attach_tracing_event(progfd, buf, reader, pid, cpu, group_fd) < 0)
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

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb, void *cb_cookie, int pid, int cpu) {
  int pfd;
  struct perf_event_attr attr = {};
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(NULL, raw_cb, cb_cookie);
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

int bpf_open_perf_event(uint32_t type, uint64_t config, int pid, int cpu) {
  int fd;
  struct perf_event_attr attr = {};

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

int bpf_attach_xdp(const char *dev_name, int progfd) {
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

    // we specify the FD passed over by the user
    nla_xdp->nla_type = 1/*IFLA_XDP_FD*/;
    nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
    memcpy((char *)nla_xdp + NLA_HDRLEN, &progfd, sizeof(progfd));
    nla->nla_len = NLA_HDRLEN + nla_xdp->nla_len;

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
        if (nh->nlmsg_pid != getpid()) {
            fprintf(stderr, "bpf: Wrong pid %d, expected %d\n",
                   nh->nlmsg_pid, getpid());
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
  if (ev_type != PERF_TYPE_HARDWARE && ev_type != PERF_TYPE_SOFTWARE) {
    fprintf(stderr, "Unsupported perf event type\n");
    return -1;
  }
  if ((ev_type == PERF_TYPE_HARDWARE && ev_config >= PERF_COUNT_HW_MAX) ||
      (ev_type == PERF_TYPE_SOFTWARE && ev_config >= PERF_COUNT_SW_MAX)) {
    fprintf(stderr, "Invalid perf event config\n");
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

int bpf_detach_perf_event(uint32_t ev_type, uint32_t ev_config) {
  // Right now, there is nothing to do, but it's a good idea to encourage
  // callers to detach anything they attach.
  return 0;
}
