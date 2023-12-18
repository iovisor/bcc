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

#include "libbpf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_alg.h>
#include <linux/if_packet.h>
#include <linux/perf_event.h>
#include <linux/pkt_cls.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/types.h>
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
#include <sys/vfs.h>
#include <unistd.h>

#include "bcc_zip.h"
#include "perf_reader.h"

// TODO: Remove this when CentOS 6 support is not needed anymore
#include "setns.h"

#include "bcc_libbpf_inc.h"

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

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

#define UNUSED(expr) do { (void)(expr); } while (0)

#define PERF_UPROBE_REF_CTR_OFFSET_SHIFT 32

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC		0xcafe4a11
#endif

struct bpf_helper {
  char *name;
  char *required_version;
};

static struct bpf_helper helpers[] = {
  {"map_lookup_elem", "3.19"},
  {"map_update_elem", "3.19"},
  {"map_delete_elem", "3.19"},
  {"probe_read", "4.1"},
  {"ktime_get_ns", "4.1"},
  {"trace_printk", "4.1"},
  {"get_prandom_u32", "4.1"},
  {"get_smp_processor_id", "4.1"},
  {"skb_store_bytes", "4.1"},
  {"l3_csum_replace", "4.1"},
  {"l4_csum_replace", "4.1"},
  {"tail_call", "4.2"},
  {"clone_redirect", "4.2"},
  {"get_current_pid_tgid", "4.2"},
  {"get_current_uid_gid", "4.2"},
  {"get_current_comm", "4.2"},
  {"get_cgroup_classid", "4.3"},
  {"skb_vlan_push", "4.3"},
  {"skb_vlan_pop", "4.3"},
  {"skb_get_tunnel_key", "4.3"},
  {"skb_set_tunnel_key", "4.3"},
  {"perf_event_read", "4.3"},
  {"redirect", "4.4"},
  {"get_route_realm", "4.4"},
  {"perf_event_output", "4.4"},
  {"skb_load_bytes", "4.5"},
  {"get_stackid", "4.6"},
  {"csum_diff", "4.6"},
  {"skb_get_tunnel_opt", "4.6"},
  {"skb_set_tunnel_opt", "4.6"},
  {"skb_change_proto", "4.8"},
  {"skb_change_type", "4.8"},
  {"skb_under_cgroup", "4.8"},
  {"get_hash_recalc", "4.8"},
  {"get_current_task", "4.8"},
  {"probe_write_user", "4.8"},
  {"current_task_under_cgroup", "4.9"},
  {"skb_change_tail", "4.9"},
  {"skb_pull_data", "4.9"},
  {"csum_update", "4.9"},
  {"set_hash_invalid", "4.9"},
  {"get_numa_node_id", "4.10"},
  {"skb_change_head", "4.10"},
  {"xdp_adjust_head", "4.10"},
  {"probe_read_str", "4.11"},
  {"get_socket_cookie", "4.12"},
  {"get_socket_uid", "4.12"},
  {"set_hash", "4.13"},
  {"setsockopt", "4.13"},
  {"skb_adjust_room", "4.13"},
  {"redirect_map", "4.14"},
  {"sk_redirect_map", "4.14"},
  {"sock_map_update", "4.14"},
  {"xdp_adjust_meta", "4.15"},
  {"perf_event_read_value", "4.15"},
  {"perf_prog_read_value", "4.15"},
  {"getsockopt", "4.15"},
  {"override_return", "4.16"},
  {"sock_ops_cb_flags_set", "4.16"},
  {"msg_redirect_map", "4.17"},
  {"msg_apply_bytes", "4.17"},
  {"msg_cork_bytes", "4.17"},
  {"msg_pull_data", "4.17"},
  {"bind", "4.17"},
  {"xdp_adjust_tail", "4.18"},
  {"skb_get_xfrm_state", "4.18"},
  {"get_stack", "4.18"},
  {"skb_load_bytes_relative", "4.18"},
  {"fib_lookup", "4.18"},
  {"sock_hash_update", "4.18"},
  {"msg_redirect_hash", "4.18"},
  {"sk_redirect_hash", "4.18"},
  {"lwt_push_encap", "4.18"},
  {"lwt_seg6_store_bytes", "4.18"},
  {"lwt_seg6_adjust_srh", "4.18"},
  {"lwt_seg6_action", "4.18"},
  {"rc_repeat", "4.18"},
  {"rc_keydown", "4.18"},
  {"skb_cgroup_id", "4.18"},
  {"get_current_cgroup_id", "4.18"},
  {"get_local_storage", "4.19"},
  {"sk_select_reuseport", "4.19"},
  {"skb_ancestor_cgroup_id", "4.19"},
  {"sk_lookup_tcp", "4.20"},
  {"sk_lookup_udp", "4.20"},
  {"sk_release", "4.20"},
  {"map_push_elem", "4.20"},
  {"map_pop_elem", "4.20"},
  {"map_peak_elem", "4.20"},
  {"msg_push_data", "4.20"},
  {"msg_pop_data", "5.0"},
  {"rc_pointer_rel", "5.0"},
  {"spin_lock", "5.1"},
  {"spin_unlock", "5.1"},
  {"sk_fullsock", "5.1"},
  {"tcp_sock", "5.1"},
  {"skb_ecn_set_ce", "5.1"},
  {"get_listener_sock", "5.1"},
  {"skc_lookup_tcp", "5.2"},
  {"tcp_check_syncookie", "5.2"},
  {"sysctl_get_name", "5.2"},
  {"sysctl_get_current_value", "5.2"},
  {"sysctl_get_new_value", "5.2"},
  {"sysctl_set_new_value", "5.2"},
  {"strtol", "5.2"},
  {"strtoul", "5.2"},
  {"sk_storage_get", "5.2"},
  {"sk_storage_delete", "5.2"},
  {"send_signal", "5.3"},
  {"tcp_gen_syncookie", "5.3"},
  {"skb_output", "5.5"},
  {"probe_read_user", "5.5"},
  {"probe_read_kernel", "5.5"},
  {"probe_read_user_str", "5.5"},
  {"probe_read_kernel_str", "5.5"},
  {"tcp_send_ack", "5.5"},
  {"send_signal_thread", "5.5"},
  {"jiffies64", "5.5"},
  {"read_branch_records", "5.6"},
  {"get_ns_current_pid_tgid", "5.6"},
  {"xdp_output", "5.6"},
  {"get_netns_cookie", "5.6"},
  {"get_current_ancestor_cgroup_id", "5.6"},
  {"sk_assign", "5.6"},
  {"ktime_get_boot_ns", "5.7"},
  {"seq_printf", "5.7"},
  {"seq_write", "5.7"},
  {"sk_cgroup_id", "5.7"},
  {"sk_ancestor_cgroup_id", "5.7"},
  {"csum_level", "5.7"},
  {"ringbuf_output", "5.8"},
  {"ringbuf_reserve", "5.8"},
  {"ringbuf_submit", "5.8"},
  {"ringbuf_discard", "5.8"},
  {"ringbuf_query", "5.8"},
  {"skc_to_tcp6_sock", "5.9"},
  {"skc_to_tcp_sock", "5.9"},
  {"skc_to_tcp_timewait_sock", "5.9"},
  {"skc_to_tcp_request_sock", "5.9"},
  {"skc_to_udp6_sock", "5.9"},
  {"get_task_stack", "5.9"},
  {"load_hdr_opt", "5.10"},
  {"store_hdr_opt", "5.10"},
  {"reserve_hdr_opt", "5.10"},
  {"inode_storage_get", "5.10"},
  {"inode_storage_delete", "5.10"},
  {"d_path", "5.10"},
  {"copy_from_user", "5.10"},
  {"snprintf_btf", "5.10"},
  {"seq_printf_btf", "5.10"},
  {"skb_cgroup_classid", "5.10"},
  {"redirect_neigh", "5.10"},
  {"per_cpu_ptr", "5.10"},
  {"this_cpu_ptr", "5.10"},
  {"redirect_peer", "5.10"},
  {"task_storage_get", "5.11"},
  {"task_storage_delete", "5.11"},
  {"get_current_task_btf", "5.11"},
  {"bprm_opts_set", "5.11"},
  {"ktime_get_coarse_ns", "5.11"},
  {"ima_inode_hash", "5.11"},
  {"sock_from_file", "5.11"},
  {"check_mtu", "5.12"},
  {"for_each_map_elem", "5.13"},
  {"snprintf", "5.13"},
  {"sys_bpf", "5.14"},
  {"btf_find_by_name_kind", "5.14"},
  {"sys_close", "5.14"},
  {"timer_init", "5.15"},
  {"timer_set_callback", "5.15"},
  {"timer_start", "5.15"},
  {"timer_cancel", "5.15"},
  {"get_func_ip", "5.15"},
  {"get_attach_cookie", "5.15"},
  {"task_pt_regs", "5.15"},
  {"get_branch_snapshot", "5.16"},
  {"trace_vprintk", "5.16"},
  {"skc_to_unix_sock", "5.16"},
  {"kallsyms_lookup_name", "5.16"},
  {"find_vma", "5.17"},
  {"loop", "5.17"},
  {"strncmp", "5.17"},
  {"get_func_arg", "5.17"},
  {"get_func_ret", "5.17"},
  {"get_func_ret", "5.17"},
  {"get_retval", "5.18"},
  {"set_retval", "5.18"},
  {"xdp_get_buff_len", "5.18"},
  {"xdp_load_bytes", "5.18"},
  {"xdp_store_bytes", "5.18"},
  {"copy_from_user_task", "5.18"},
  {"skb_set_tstamp", "5.18"},
  {"ima_file_hash", "5.18"},
  {"kptr_xchg", "5.19"},
  {"map_lookup_percpu_elem", "5.19"},
  {"skc_to_mptcp_sock", "5.19"},
  {"dynptr_from_mem", "5.19"},
  {"ringbuf_reserve_dynptr", "5.19"},
  {"ringbuf_submit_dynptr", "5.19"},
  {"ringbuf_discard_dynptr", "5.19"},
  {"dynptr_read", "5.19"},
  {"dynptr_write", "5.19"},
  {"dynptr_data", "5.19"},
  {"tcp_raw_gen_syncookie_ipv4", "6.0"},
  {"tcp_raw_gen_syncookie_ipv6", "6.0"},
  {"tcp_raw_check_syncookie_ipv4", "6.0"},
  {"tcp_raw_check_syncookie_ipv6", "6.0"},
  {"ktime_get_tai_ns", "6.1"},
  {"user_ringbuf_drain", "6.1"},
  {"cgrp_storage_get", "6.2"},
  {"cgrp_storage_delete", "6.2"},
};

static uint64_t ptr_to_u64(void *ptr)
{
  return (uint64_t) (unsigned long) ptr;
}

static int libbpf_bpf_map_create(struct bcc_create_map_attr *create_attr)
{
  LIBBPF_OPTS(bpf_map_create_opts, p);

  p.map_flags = create_attr->map_flags;
  p.numa_node = create_attr->numa_node;
  p.btf_fd = create_attr->btf_fd;
  p.btf_key_type_id = create_attr->btf_key_type_id;
  p.btf_value_type_id = create_attr->btf_value_type_id;
  p.map_ifindex = create_attr->map_ifindex;
  if (create_attr->map_type == BPF_MAP_TYPE_STRUCT_OPS)
    p.btf_vmlinux_value_type_id = create_attr->btf_vmlinux_value_type_id;
  else
    p.inner_map_fd = create_attr->inner_map_fd;

  return bpf_map_create(create_attr->map_type, create_attr->name, create_attr->key_size,
                        create_attr->value_size, create_attr->max_entries, &p);
}

int bcc_create_map_xattr(struct bcc_create_map_attr *attr, bool allow_rlimit)
{
  unsigned name_len = attr->name ? strlen(attr->name) : 0;
  char map_name[BPF_OBJ_NAME_LEN] = {};

  memcpy(map_name, attr->name, min(name_len, BPF_OBJ_NAME_LEN - 1));
  attr->name = map_name;
  int ret = libbpf_bpf_map_create(attr);

  if (ret < 0 && errno == EPERM) {
    if (!allow_rlimit)
      return ret;

    // see note below about the rationale for this retry
    struct rlimit rl = {};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
      rl.rlim_max = RLIM_INFINITY;
      rl.rlim_cur = rl.rlim_max;
      if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        ret = libbpf_bpf_map_create(attr);
    }
  }

  // kernel already supports btf if its loading is successful,
  // but this map type may not support pretty print yet.
  if (ret < 0 && attr->btf_key_type_id && errno == 524 /* ENOTSUPP */) {
    attr->btf_fd = 0;
    attr->btf_key_type_id = 0;
    attr->btf_value_type_id = 0;
    ret = libbpf_bpf_map_create(attr);
  }

  if (ret < 0 && name_len && (errno == E2BIG || errno == EINVAL)) {
    map_name[0] = '\0';
    ret = libbpf_bpf_map_create(attr);
  }

  if (ret < 0 && errno == EPERM) {
    if (!allow_rlimit)
      return ret;

    // see note below about the rationale for this retry
    struct rlimit rl = {};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
      rl.rlim_max = RLIM_INFINITY;
      rl.rlim_cur = rl.rlim_max;
      if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
        ret = libbpf_bpf_map_create(attr);
    }
  }
  return ret;
}

int bcc_create_map(enum bpf_map_type map_type, const char *name,
                   int key_size, int value_size,
                   int max_entries, int map_flags)
{
  struct bcc_create_map_attr attr = {};

  attr.map_type = map_type;
  attr.name = name;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;
  return bcc_create_map_xattr(&attr, true);
}

int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
  return bpf_map_update_elem(fd, key, value, flags);
}

int bpf_lookup_elem(int fd, void *key, void *value)
{
  return bpf_map_lookup_elem(fd, key, value);
}

int bpf_delete_elem(int fd, void *key)
{
  return bpf_map_delete_elem(fd, key);
}

int bpf_lookup_and_delete(int fd, void *key, void *value)
{
  return bpf_map_lookup_and_delete_elem(fd, key, value);
}

int bpf_lookup_batch(int fd, __u32 *in_batch, __u32 *out_batch, void *keys,
                     void *values, __u32 *count)
{
  return bpf_map_lookup_batch(fd, in_batch, out_batch, keys, values, count,
                              NULL);
}

int bpf_delete_batch(int fd,  void *keys, __u32 *count)
{
  return bpf_map_delete_batch(fd, keys, count, NULL);
}

int bpf_update_batch(int fd, void *keys, void *values, __u32 *count)
{
  return bpf_map_update_batch(fd, keys, values, count, NULL);
}

int bpf_lookup_and_delete_batch(int fd, __u32 *in_batch, __u32 *out_batch,
                                void *keys, void *values, __u32 *count)
{
  return bpf_map_lookup_and_delete_batch(fd, in_batch, out_batch, keys, values,
                                         count, NULL);
}

int bpf_get_first_key(int fd, void *key, size_t key_size)
{
  int i, res;

  // 4.12 and above kernel supports passing NULL to BPF_MAP_GET_NEXT_KEY
  // to get first key of the map. For older kernels, the call will fail.
  res = bpf_map_get_next_key(fd, 0, key);
  if (res < 0 && errno == EFAULT) {
    // Fall back to try to find a non-existing key.
    static unsigned char try_values[3] = {0, 0xff, 0x55};
    for (i = 0; i < 3; i++) {
      memset(key, try_values[i], key_size);
      // We want to check the existence of the key but we don't know the size
      // of map's value. So we pass an invalid pointer for value, expect
      // the call to fail and check if the error is ENOENT indicating the
      // key doesn't exist. If we use NULL for the invalid pointer, it might
      // trigger a page fault in kernel and affect performance. Hence we use
      // ~0 which will fail and return fast.
      // This should fail since we pass an invalid pointer for value.
      if (bpf_map_lookup_elem(fd, key, (void *)~0) >= 0)
        return -1;
      // This means the key doesn't exist.
      if (errno == ENOENT)
        return bpf_map_get_next_key(fd, (void*)&try_values[i], key);
    }
    return -1;
  } else {
    return res;
  }
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
  return bpf_map_get_next_key(fd, key, next_key);
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
      "bpf_probe_read_kernel() to copy it to the BPF stack. Sometimes the "
      "bpf_probe_read_kernel() is automatic by the bcc rewriter, other times "
      "you'll need to be explicit.\n\n");
  }

  // referencing global/static variables or read only data
  if (strstr(log, "unknown opcode") != NULL) {
    fprintf(stderr, "HINT: The 'unknown opcode' can happen if you reference "
      "a global or static variable, or data in read-only section. For example,"
      " 'char *p = \"hello\"' will result in p referencing a read-only section,"
      " and 'char p[] = \"hello\"' will have \"hello\" stored on the stack.\n\n");
  }

  // helper function not found in kernel
  char *helper_str = strstr(log, "invalid func ");
  if (helper_str != NULL) {
    helper_str += strlen("invalid func ");
    char *str = strchr(helper_str, '#');
    if (str != NULL) {
      helper_str = str + 1;
    }
    int helper_id = atoi(helper_str);
    if (helper_id && helper_id < sizeof(helpers) / sizeof(struct bpf_helper)) {
      struct bpf_helper helper = helpers[helper_id - 1];
      fprintf(stderr, "HINT: bpf_%s missing (added in Linux %s).\n\n",
              helper.name, helper.required_version);
    }
  }
}
#define ROUND_UP(x, n) (((x) + (n) - 1u) & ~((n) - 1u))

int bpf_obj_get_info(int prog_map_fd, void *info, uint32_t *info_len)
{
  return bpf_obj_get_info_by_fd(prog_map_fd, info, info_len);
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
  close(shafd2);
  close(shafd);
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
  unsigned long long tag = 0;
  // prog_tag: can appear in different lines
  while (fgets(fmt, sizeof(fmt), f)) {
    if (sscanf(fmt, "prog_tag:%llx", &tag) == 1) {
      *ptag = tag;
      fclose(f);
      return 0;
    }
  }
  fclose(f);
  return -2;
}

static int libbpf_bpf_prog_load(enum bpf_prog_type prog_type,
                                const char *prog_name, const char *license,
                                const struct bpf_insn *insns, size_t insn_cnt,
                                struct bpf_prog_load_opts *opts,
                                char *log_buf, size_t log_buf_sz)
{

  LIBBPF_OPTS(bpf_prog_load_opts, p);

  if (!opts || !log_buf != !log_buf_sz) {
    errno = EINVAL;
    return -EINVAL;
  }

  p.expected_attach_type = opts->expected_attach_type;
  switch (prog_type) {
  case BPF_PROG_TYPE_STRUCT_OPS:
  case BPF_PROG_TYPE_LSM:
    p.attach_btf_id = opts->attach_btf_id;
    break;
  case BPF_PROG_TYPE_TRACING:
  case BPF_PROG_TYPE_EXT:
    p.attach_btf_id = opts->attach_btf_id;
    p.attach_prog_fd = opts->attach_prog_fd;
    p.attach_btf_obj_fd = opts->attach_btf_obj_fd;
    break;
  default:
    p.prog_ifindex = opts->prog_ifindex;
    p.kern_version = opts->kern_version;
  }
  p.log_level = opts->log_level;
  p.log_buf = log_buf;
  p.log_size = log_buf_sz;
  p.prog_btf_fd = opts->prog_btf_fd;
  p.func_info_rec_size = opts->func_info_rec_size;
  p.func_info_cnt = opts->func_info_cnt;
  p.func_info = opts->func_info;
  p.line_info_rec_size = opts->line_info_rec_size;
  p.line_info_cnt = opts->line_info_cnt;
  p.line_info = opts->line_info;
  p.prog_flags = opts->prog_flags;

  return bpf_prog_load(prog_type, prog_name, license,
                       insns, insn_cnt, &p);
}

static int find_btf_id(const char *module_name, const char *func_name,
                       enum bpf_attach_type expected_attach_type, int *btf_fd)
{
  struct btf *vmlinux_btf = NULL, *module_btf = NULL;
  struct bpf_btf_info info;
  int err, fd, btf_id;
  __u32 id = 0, len;
  char name[64];

  if (!module_name[0] || !strcmp(module_name, "vmlinux"))
    return libbpf_find_vmlinux_btf_id(func_name, expected_attach_type);

  while (true) {
    err = bpf_btf_get_next_id(id, &id);
    if (err) {
      fprintf(stderr, "bpf_btf_get_next_id failed: %d\n", err);
      return err;
    }

    fd = bpf_btf_get_fd_by_id(id);
    if (fd < 0) {
      err = fd;
      fprintf(stderr, "bpf_btf_get_fd_by_id failed: %d\n", err);
      return err;
    }

    len = sizeof(info);
    memset(&info, 0, sizeof(info));
    info.name = ptr_to_u64(name);
    info.name_len = sizeof(name);

    err = bpf_btf_get_info_by_fd(fd, &info, &len);
    if (err) {
      fprintf(stderr, "bpf_btf_get_info_by_fd failed: %d\n", err);
      goto err_out;
    }

    if (!info.kernel_btf || strcmp(name, module_name)) {
      close(fd);
      continue;
    }

    vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(vmlinux_btf);
    if (err) {
      fprintf(stderr, "btf__load_vmlinux_btf failed: %d\n", err);
      goto err_out;
    }

    module_btf = btf__load_module_btf(module_name, vmlinux_btf);
    err = libbpf_get_error(vmlinux_btf);
    if (err) {
      fprintf(stderr, "btf__load_module_btf failed: %d\n", err);
      goto err_out;
    }

    btf_id = btf__find_by_name_kind(module_btf, func_name, BTF_KIND_FUNC);
    if (btf_id < 0) {
      err = btf_id;
      fprintf(stderr, "btf__find_by_name_kind failed: %d\n", err);
      goto err_out;
    }

    btf__free(module_btf);
    btf__free(vmlinux_btf);

    *btf_fd = fd;
    return btf_id;

err_out:
    btf__free(module_btf);
    btf__free(vmlinux_btf);
    close(fd);
    *btf_fd = -1;
    return err;
  }

  return -1;
}

int bcc_prog_load_xattr(enum bpf_prog_type prog_type, const char *prog_name,
                        const char *license, const struct bpf_insn *insns,
                        struct bpf_prog_load_opts *opts, int prog_len,
                        char *log_buf, unsigned log_buf_size, bool allow_rlimit)
{
  unsigned name_len = prog_name ? strlen(prog_name) : 0;
  char *tmp_log_buf = NULL, *opts_log_buf = NULL;
  unsigned tmp_log_buf_size = 0, opts_log_buf_size = 0;
  int ret = 0, name_offset = 0, expected_attach_type = 0;
  char new_prog_name[BPF_OBJ_NAME_LEN] = {};
  char mod_name[64] = {};
  char *mod_end;
  int mod_len;
  int fd = -1;

  unsigned insns_cnt = prog_len / sizeof(struct bpf_insn);

  if (opts->log_level > 0) {
    if (log_buf_size > 0) {
      // Use user-provided log buffer if available.
      log_buf[0] = 0;
      opts_log_buf = log_buf;
      opts_log_buf_size = log_buf_size;
    } else {
      // Create and use temporary log buffer if user didn't provide one.
      tmp_log_buf_size = LOG_BUF_SIZE;
      tmp_log_buf = malloc(tmp_log_buf_size);
      if (!tmp_log_buf) {
        fprintf(stderr, "bpf: Failed to allocate temporary log buffer: %s\n\n",
                strerror(errno));
        opts->log_level = 0;
      } else {
        tmp_log_buf[0] = 0;
        opts_log_buf = tmp_log_buf;
        opts_log_buf_size = tmp_log_buf_size;
      }
    }
  }

  if (name_len) {
    if (strncmp(prog_name, "kprobe__", 8) == 0)
      name_offset = 8;
    else if (strncmp(prog_name, "kretprobe__", 11) == 0)
      name_offset = 11;
    else if (strncmp(prog_name, "tracepoint__", 12) == 0)
      name_offset = 12;
    else if (strncmp(prog_name, "raw_tracepoint__", 16) == 0)
      name_offset = 16;
    else if (strncmp(prog_name, "kfunc__", 7) == 0) {
      // kfunc__vmlinux__vfs_read
      mod_end = strstr(prog_name + 7, "__");
      mod_len = mod_end - prog_name - 7;
      strncpy(mod_name, prog_name + 7, mod_len);
      name_offset = 7 + mod_len + 2;
      expected_attach_type = BPF_TRACE_FENTRY;
    } else if (strncmp(prog_name, "kmod_ret__", 10) == 0) {
      name_offset = 10;
      expected_attach_type = BPF_MODIFY_RETURN;
    } else if (strncmp(prog_name, "kretfunc__", 10) == 0) {
      // kretfunc__vmlinux__vfs_read
      mod_end = strstr(prog_name + 10, "__");
      mod_len = mod_end - prog_name - 10;
      strncpy(mod_name, prog_name + 10, mod_len);
      name_offset = 10 + mod_len + 2;
      expected_attach_type = BPF_TRACE_FEXIT;
    } else if (strncmp(prog_name, "lsm__", 5) == 0) {
      name_offset = 5;
      expected_attach_type = BPF_LSM_MAC;
    } else if (strncmp(prog_name, "bpf_iter__", 10) == 0) {
      name_offset = 10;
      expected_attach_type = BPF_TRACE_ITER;
    }

    if (prog_type == BPF_PROG_TYPE_TRACING ||
        prog_type == BPF_PROG_TYPE_LSM) {
      ret = find_btf_id(mod_name, prog_name + name_offset,
                        expected_attach_type, &fd);
      if (ret == -EINVAL) {
        fprintf(stderr, "bpf: %s BTF is not found\n", mod_name);
        return ret;
      } else if (ret < 0) {
        fprintf(stderr, "bpf: %s is not found in %s BTF\n",
                prog_name + name_offset, mod_name);
        return ret;
      }

      opts->attach_btf_obj_fd = fd == -1 ? 0 : fd;
      opts->attach_btf_id = ret;
      opts->expected_attach_type = expected_attach_type;
    }

    memcpy(new_prog_name, prog_name + name_offset,
           min(name_len - name_offset, BPF_OBJ_NAME_LEN - 1));
  }

  ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);

  // func_info/line_info may not be supported in old kernels.
  if (ret < 0 && opts->func_info && errno == EINVAL) {
    opts->prog_btf_fd = 0;
    opts->func_info = NULL;
    opts->func_info_cnt = 0;
    opts->func_info_rec_size = 0;
    opts->line_info = NULL;
    opts->line_info_cnt = 0;
    opts->line_info_rec_size = 0;
    ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);
  }

  // BPF object name is not supported on older Kernels.
  // If we failed due to this, clear the name and try again.
  if (ret < 0 && name_len && (errno == E2BIG || errno == EINVAL)) {
    new_prog_name[0] = '\0';
    ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);
  }

  if (ret < 0 && errno == EPERM) {
    if (!allow_rlimit)
      return ret;

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
        ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, opts_log_buf, opts_log_buf_size);
    }
  }

  if (ret < 0 && errno == E2BIG) {
    fprintf(stderr,
            "bpf: %s. Program %s too large (%u insns), at most %d insns\n\n",
            strerror(errno), new_prog_name, insns_cnt, BPF_MAXINSNS);
    return -1;
  }

  // The load has failed. Handle log message.
  if (ret < 0) {
    // User has provided a log buffer.
    if (log_buf_size) {
      // If logging is not already enabled, enable it and do the syscall again.
      if (opts->log_level == 0) {
        opts->log_level = 1;
        ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, log_buf, log_buf_size);
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
    if (opts->log_level == 0)
      opts->log_level = 1;
    for (;;) {
      tmp_log_buf = malloc(tmp_log_buf_size);
      if (!tmp_log_buf) {
        fprintf(stderr, "bpf: Failed to allocate temporary log buffer: %s\n\n",
                strerror(errno));
        goto return_result;
      }
      tmp_log_buf[0] = 0;
      ret = libbpf_bpf_prog_load(prog_type, new_prog_name, license, insns, insns_cnt, opts, tmp_log_buf, tmp_log_buf_size);
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
  if (opts->log_level > 0) {
    // Don't print if user enabled logging and provided log buffer,
    // but there is no error.
    if (log_buf && ret < 0)
      bpf_print_hints(ret, log_buf);
    else if (tmp_log_buf)
      bpf_print_hints(ret, tmp_log_buf);
  }

return_result:
  if (fd >= 0)
    close(fd);
  if (tmp_log_buf)
    free(tmp_log_buf);
  return ret;
}

int bcc_prog_load(enum bpf_prog_type prog_type, const char *name,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned kern_version,
                  int log_level, char *log_buf, unsigned log_buf_size)
{
  struct bpf_prog_load_opts opts = {};


  if (prog_type != BPF_PROG_TYPE_TRACING && prog_type != BPF_PROG_TYPE_EXT)
    opts.kern_version = kern_version;
  opts.log_level = log_level;
  return bcc_prog_load_xattr(prog_type, name, license, insns, &opts, prog_len, log_buf, log_buf_size, true);
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

#define PMU_TYPE_FILE "/sys/bus/event_source/devices/%s/type"
static int bpf_find_probe_type(const char *event_type)
{
  int fd;
  int ret;
  char buf[PATH_MAX];

  ret = snprintf(buf, sizeof(buf), PMU_TYPE_FILE, event_type);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;

  fd = open(buf, O_RDONLY);
  if (fd < 0)
    return -1;
  ret = read(fd, buf, sizeof(buf));
  close(fd);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;
  errno = 0;
  ret = (int)strtol(buf, NULL, 10);
  return errno ? -1 : ret;
}

#define PMU_RETPROBE_FILE "/sys/bus/event_source/devices/%s/format/retprobe"
static int bpf_get_retprobe_bit(const char *event_type)
{
  int fd;
  int ret;
  char buf[PATH_MAX];

  ret = snprintf(buf, sizeof(buf), PMU_RETPROBE_FILE, event_type);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;

  fd = open(buf, O_RDONLY);
  if (fd < 0)
    return -1;
  ret = read(fd, buf, sizeof(buf));
  close(fd);
  if (ret < 0 || ret >= sizeof(buf))
    return -1;
  if (strncmp(buf, "config:", strlen("config:")))
    return -1;
  errno = 0;
  ret = (int)strtol(buf + strlen("config:"), NULL, 10);
  return errno ? -1 : ret;
}

/*
 * Kernel API with e12f03d ("perf/core: Implement the 'perf_kprobe' PMU") allows
 * creating [k,u]probe with perf_event_open, which makes it easier to clean up
 * the [k,u]probe. This function tries to create pfd with the perf_kprobe PMU.
 */
static int bpf_try_perf_event_open_with_probe(const char *name, uint64_t offs,
             int pid, const char *event_type, int is_return,
             uint64_t ref_ctr_offset)
{
  struct perf_event_attr attr = {};
  int type = bpf_find_probe_type(event_type);
  int is_return_bit = bpf_get_retprobe_bit(event_type);
  int cpu = 0;

  if (type < 0 || is_return_bit < 0)
    return -1;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  if (is_return)
    attr.config |= 1 << is_return_bit;
  attr.config |= (ref_ctr_offset << PERF_UPROBE_REF_CTR_OFFSET_SHIFT);

  /*
   * struct perf_event_attr in latest perf_event.h has the following
   * extension to config1 and config2. To keep bcc compatibe with
   * older perf_event.h, we use config1 and config2 here instead of
   * kprobe_func, uprobe_path, kprobe_addr, and probe_offset.
   *
   * union {
   *  __u64 bp_addr;
   *  __u64 kprobe_func;
   *  __u64 uprobe_path;
   *  __u64 config1;
   * };
   * union {
   *   __u64 bp_len;
   *   __u64 kprobe_addr;
   *   __u64 probe_offset;
   *   __u64 config2;
   * };
   */
  attr.config2 = offs;  /* config2 here is kprobe_addr or probe_offset */
  attr.size = sizeof(attr);
  attr.type = type;
  /* config1 here is kprobe_func or  uprobe_path */
  attr.config1 = ptr_to_u64((void *)name);
  // PID filter is only possible for uprobe events.
  if (pid < 0)
    pid = -1;
  // perf_event_open API doesn't allow both pid and cpu to be -1.
  // So only set it to -1 when PID is not -1.
  // Tracing events do not do CPU filtering in any cases.
  if (pid != -1)
    cpu = -1;
  return syscall(__NR_perf_event_open, &attr, pid, cpu, -1 /* group_fd */,
                 PERF_FLAG_FD_CLOEXEC);
}

#define DEBUGFS_TRACEFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

static const char *get_tracefs_path()
{
  if (access(DEBUGFS_TRACEFS, F_OK) == 0) {
    return DEBUGFS_TRACEFS;
  }
  return TRACEFS;
}


// When a valid Perf Event FD provided through pfd, it will be used to enable
// and attach BPF program to the event, and event_path will be ignored.
// Otherwise, event_path is expected to contain the path to the event in tracefs
// and it will be used to open the Perf Event FD.
// In either case, if the attach partially failed (such as issue with the
// ioctl operations), the **caller** need to clean up the Perf Event FD, either
// provided by the caller or opened here.
static int bpf_attach_tracing_event(int progfd, const char *event_path, int pid,
                                    int *pfd)
{
  int efd, cpu = 0;
  ssize_t bytes;
  char buf[PATH_MAX];
  struct perf_event_attr attr = {};
  // Caller did not provide a valid Perf Event FD. Create one with the tracefs
  // event path provided.
  if (*pfd < 0) {
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
    *pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
    if (*pfd < 0) {
      fprintf(stderr, "perf_event_open(%s/id): %s\n", event_path, strerror(errno));
      return -1;
    }
  }

  if (ioctl(*pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
    return -1;
  }
  if (ioctl(*pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    return -1;
  }

  return 0;
}

/* Creates an [uk]probe using tracefs.
 * On success, the path to the probe is placed in buf (which is assumed to be of size PATH_MAX).
 */
static int create_probe_event(char *buf, const char *ev_name,
                              enum bpf_probe_attach_type attach_type,
                              const char *config1, uint64_t offset,
                              const char *event_type, pid_t pid, int maxactive)
{
  int kfd = -1, res = -1;
  char ev_alias[256];
  bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

  snprintf(buf, PATH_MAX, "%s/%s_events", get_tracefs_path(), event_type);
  kfd = open(buf, O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    fprintf(stderr, "%s: open(%s): %s\n", __func__, buf,
            strerror(errno));
    return -1;
  }

  res = snprintf(ev_alias, sizeof(ev_alias), "%s_bcc_%d", ev_name, getpid());
  if (res < 0 || res >= sizeof(ev_alias)) {
    fprintf(stderr, "Event name (%s) is too long for buffer\n", ev_name);
    close(kfd);
    goto error;
  }

  if (is_kprobe) {
    if (offset > 0 && attach_type == BPF_PROBE_ENTRY)
      snprintf(buf, PATH_MAX, "p:kprobes/%s %s+%"PRIu64,
               ev_alias, config1, offset);
    else if (maxactive > 0 && attach_type == BPF_PROBE_RETURN)
      snprintf(buf, PATH_MAX, "r%d:kprobes/%s %s",
               maxactive, ev_alias, config1);
    else
      snprintf(buf, PATH_MAX, "%c:kprobes/%s %s",
               attach_type == BPF_PROBE_ENTRY ? 'p' : 'r',
               ev_alias, config1);
  } else {
    res = snprintf(buf, PATH_MAX, "%c:%ss/%s %s:0x%lx", attach_type==BPF_PROBE_ENTRY ? 'p' : 'r',
                   event_type, ev_alias, config1, (unsigned long)offset);
    if (res < 0 || res >= PATH_MAX) {
      fprintf(stderr, "Event alias (%s) too long for buffer\n", ev_alias);
      close(kfd);
      return -1;
    }
  }

  if (write(kfd, buf, strlen(buf)) < 0) {
    if (errno == ENOENT)
      fprintf(stderr, "cannot attach %s, probe entry may not exist\n", event_type);
    else
      fprintf(stderr, "cannot attach %s, %s\n", event_type, strerror(errno));
    close(kfd);
    goto error;
  }
  close(kfd);
  snprintf(buf, PATH_MAX, "%s/events/%ss/%s", get_tracefs_path(),
           event_type, ev_alias);
  return 0;
error:
  return -1;
}

// config1 could be either kprobe_func or uprobe_path,
// see bpf_try_perf_event_open_with_probe().
static int bpf_attach_probe(int progfd, enum bpf_probe_attach_type attach_type,
                            const char *ev_name, const char *config1, const char* event_type,
                            uint64_t offset, pid_t pid, int maxactive,
                            uint32_t ref_ctr_offset)
{
  int kfd, pfd = -1;
  char buf[PATH_MAX], fname[256], kprobe_events[PATH_MAX];
  bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

  if (maxactive <= 0)
    // Try create the [k,u]probe Perf Event with perf_event_open API.
    pfd = bpf_try_perf_event_open_with_probe(config1, offset, pid, event_type,
                                             attach_type != BPF_PROBE_ENTRY,
                                             ref_ctr_offset);

  // If failed, most likely Kernel doesn't support the perf_kprobe PMU
  // (e12f03d "perf/core: Implement the 'perf_kprobe' PMU") yet.
  // Try create the event using tracefs.
  if (pfd < 0) {
    if (create_probe_event(buf, ev_name, attach_type, config1, offset,
                           event_type, pid, maxactive) < 0)
      goto error;

    // If we're using maxactive, we need to check that the event was created
    // under the expected name.  If tracefs doesn't support maxactive yet
    // (kernel < 4.12), the event is created under a different name; we need to
    // delete that event and start again without maxactive.
    if (is_kprobe && maxactive > 0 && attach_type == BPF_PROBE_RETURN) {
      if (snprintf(fname, sizeof(fname), "%s/id", buf) >= sizeof(fname)) {
        fprintf(stderr, "filename (%s) is too long for buffer\n", buf);
        goto error;
      }
      if (access(fname, F_OK) == -1) {
        snprintf(kprobe_events, PATH_MAX, "%s/kprobe_events", get_tracefs_path());
        // Deleting kprobe event with incorrect name.
        kfd = open(kprobe_events, O_WRONLY | O_APPEND, 0);
        if (kfd < 0) {
          fprintf(stderr, "open(%s): %s\n", kprobe_events, strerror(errno));
          return -1;
        }
        snprintf(fname, sizeof(fname), "-:kprobes/%s_0", ev_name);
        if (write(kfd, fname, strlen(fname)) < 0) {
          if (errno == ENOENT)
            fprintf(stderr, "cannot detach kprobe, probe entry may not exist\n");
          else
            fprintf(stderr, "cannot detach kprobe, %s\n", strerror(errno));
          close(kfd);
          goto error;
        }
        close(kfd);

        // Re-creating kprobe event without maxactive.
        if (create_probe_event(buf, ev_name, attach_type, config1,
                               offset, event_type, pid, 0) < 0)
          goto error;
      }
    }
  }
  // If perf_event_open succeeded, bpf_attach_tracing_event will use the created
  // Perf Event FD directly and buf would be empty and unused.
  // Otherwise it will read the event ID from the path in buf, create the
  // Perf Event event using that ID, and updated value of pfd.
  if (bpf_attach_tracing_event(progfd, buf, pid, &pfd) == 0)
    return pfd;

error:
  bpf_close_perf_event_fd(pfd);
  return -1;
}

int bpf_attach_kprobe(int progfd, enum bpf_probe_attach_type attach_type,
                      const char *ev_name, const char *fn_name,
                      uint64_t fn_offset, int maxactive)
{
  return bpf_attach_probe(progfd, attach_type,
                          ev_name, fn_name, "kprobe",
                          fn_offset, -1, maxactive, 0);
}

static int _find_archive_path_and_offset(const char *entry_path,
                                         char out_path[PATH_MAX],
                                         uint64_t *offset) {
  const char *separator = strstr(entry_path, "!/");
  if (separator == NULL || (separator - entry_path) >= PATH_MAX) {
    return -1;
  }

  struct bcc_zip_entry entry;
  struct bcc_zip_archive *archive =
      bcc_zip_archive_open_and_find(entry_path, &entry);
  if (archive == NULL) {
    return -1;
  }
  if (entry.compression) {
    bcc_zip_archive_close(archive);
    return -1;
  }

  strncpy(out_path, entry_path, separator - entry_path);
  out_path[separator - entry_path] = 0;
  *offset += entry.data_offset;

  bcc_zip_archive_close(archive);
  return 0;
}

int bpf_attach_uprobe(int progfd, enum bpf_probe_attach_type attach_type,
                      const char *ev_name, const char *binary_path,
                      uint64_t offset, pid_t pid, uint32_t ref_ctr_offset)
{
  char archive_path[PATH_MAX];
  if (access(binary_path, F_OK) != 0 &&
      _find_archive_path_and_offset(binary_path, archive_path, &offset) == 0) {
    binary_path = archive_path;
  }

  return bpf_attach_probe(progfd, attach_type,
                          ev_name, binary_path, "uprobe",
                          offset, pid, -1, ref_ctr_offset);
}

static int bpf_detach_probe(const char *ev_name, const char *event_type)
{
  int kfd = -1, res;
  char buf[PATH_MAX];
  int found_event = 0;
  size_t bufsize = 0;
  char *cptr = NULL;
  FILE *fp;

  /*
   * For [k,u]probe created with perf_event_open (on newer kernel), it is
   * not necessary to clean it up in [k,u]probe_events. We first look up
   * the %s_bcc_%d line in [k,u]probe_events. If the event is not found,
   * it is safe to skip the cleaning up process (write -:... to the file).
   */
  snprintf(buf, sizeof(buf), "%s/%s_events", get_tracefs_path(), event_type);
  fp = fopen(buf, "r");
  if (!fp) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    goto error;
  }

  res = snprintf(buf, sizeof(buf), "%ss/%s_bcc_%d", event_type, ev_name, getpid());
  if (res < 0 || res >= sizeof(buf)) {
    fprintf(stderr, "snprintf(%s): %d\n", ev_name, res);
    goto error;
  }

  while (getline(&cptr, &bufsize, fp) != -1)
    if (strstr(cptr, buf) != NULL) {
      found_event = 1;
      break;
    }
  free(cptr);
  fclose(fp);
  fp = NULL;

  if (!found_event)
    return 0;

  snprintf(buf, sizeof(buf), "%s/%s_events", get_tracefs_path(), event_type);
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
  if (fp)
    fclose(fp);
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

int bpf_attach_tracepoint(int progfd, const char *tp_category,
                          const char *tp_name)
{
  char buf[256];
  int pfd = -1;

  snprintf(buf, sizeof(buf), "%s/events/%s/%s", get_tracefs_path(), tp_category, tp_name);
  if (bpf_attach_tracing_event(progfd, buf, -1 /* PID */, &pfd) == 0)
    return pfd;

  bpf_close_perf_event_fd(pfd);
  return -1;
}

int bpf_detach_tracepoint(const char *tp_category, const char *tp_name) {
  UNUSED(tp_category);
  UNUSED(tp_name);
  // Right now, there is nothing to do, but it's a good idea to encourage
  // callers to detach anything they attach.
  return 0;
}

int bpf_attach_raw_tracepoint(int progfd, const char *tp_name)
{
  int ret;

  ret = bpf_raw_tracepoint_open(tp_name, progfd);
  if (ret < 0)
    fprintf(stderr, "bpf_attach_raw_tracepoint (%s): %s\n", tp_name, strerror(errno));
  return ret;
}

bool bpf_has_kernel_btf(void)
{
  struct btf *btf;
  int err;

  btf = btf__parse_raw("/sys/kernel/btf/vmlinux");
  err = libbpf_get_error(btf);
  if (err)
    return false;

  btf__free(btf);
  return true;
}

static int find_member_by_name(struct btf *btf, const struct btf_type *btf_type, const char *field_name) {
  const struct btf_member *btf_member = btf_members(btf_type);
  int i;

  for (i = 0; i < btf_vlen(btf_type); i++, btf_member++) {
    const char *name = btf__name_by_offset(btf, btf_member->name_off);
    if (!strcmp(name, field_name)) {
      return 1;
    } else if (name[0] == '\0') {
      if (find_member_by_name(btf, btf__type_by_id(btf, btf_member->type), field_name))
        return 1;
    }
  }
  return 0;
}

int kernel_struct_has_field(const char *struct_name, const char *field_name)
{
  const struct btf_type *btf_type;
  struct btf *btf;
  int ret, btf_id;

  btf = btf__load_vmlinux_btf();
  ret = libbpf_get_error(btf);
  if (ret)
    return -1;

  btf_id = btf__find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
  if (btf_id < 0) {
    ret = -1;
    goto cleanup;
  }

  btf_type = btf__type_by_id(btf, btf_id);
  ret = find_member_by_name(btf, btf_type, field_name);

cleanup:
  btf__free(btf);
  return ret;
}

int bpf_attach_kfunc(int prog_fd)
{
  int ret;

  ret = bpf_raw_tracepoint_open(NULL, prog_fd);
  if (ret < 0)
    fprintf(stderr, "bpf_attach_raw_tracepoint (kfunc): %s\n", strerror(errno));
  return ret;
}

int bpf_attach_lsm(int prog_fd)
{
  int ret;

  ret = bpf_raw_tracepoint_open(NULL, prog_fd);
  if (ret < 0)
    fprintf(stderr, "bpf_attach_raw_tracepoint (lsm): %s\n", strerror(errno));
  return ret;
}

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb,
                            perf_reader_lost_cb lost_cb, void *cb_cookie,
                            int pid, int cpu, int page_cnt)
{
  struct bcc_perf_buffer_opts opts = {
    .pid = pid,
    .cpu = cpu,
    .wakeup_events = 1,
  };

  return bpf_open_perf_buffer_opts(raw_cb, lost_cb, cb_cookie, page_cnt, &opts);
}

void * bpf_open_perf_buffer_opts(perf_reader_raw_cb raw_cb,
                            perf_reader_lost_cb lost_cb, void *cb_cookie,
                            int page_cnt, struct bcc_perf_buffer_opts *opts)
{
  int pfd, pid = opts->pid, cpu = opts->cpu;
  struct perf_event_attr attr = {};
  struct perf_reader *reader = NULL;

  reader = perf_reader_new(raw_cb, lost_cb, cb_cookie, page_cnt);
  if (!reader)
    goto error;

  attr.config = 10;//PERF_COUNT_SW_BPF_OUTPUT;
  attr.type = PERF_TYPE_SOFTWARE;
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.sample_period = 1;
  attr.wakeup_events = opts->wakeup_events;
  pfd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
  if (pfd < 0) {
    fprintf(stderr, "perf_event_open: %s\n", strerror(errno));
    fprintf(stderr, "   (check your kernel for PERF_COUNT_SW_BPF_OUTPUT support, 4.4 or newer)\n");
    goto error;
  }
  perf_reader_set_fd(reader, pfd);

  if (perf_reader_mmap(reader) < 0)
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
  int ifindex = if_nametoindex(dev_name);
  char err_buf[256];
  int ret = -1;

  if (ifindex == 0) {
    fprintf(stderr, "bpf: Resolving device name to index: %s\n", strerror(errno));
    return -1;
  }

  ret = bpf_xdp_attach(ifindex, progfd, flags, NULL);
  if (ret) {
    libbpf_strerror(ret, err_buf, sizeof(err_buf));
    fprintf(stderr, "bpf: Attaching prog to %s: %s\n", dev_name, err_buf);
    return -1;
  }

  return 0;
}

int bpf_attach_perf_event_raw(int progfd, void *perf_event_attr, pid_t pid,
                              int cpu, int group_fd, unsigned long extra_flags) {
  int fd = syscall(__NR_perf_event_open, perf_event_attr, pid, cpu, group_fd,
                   PERF_FLAG_FD_CLOEXEC | extra_flags);
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

  return bpf_attach_perf_event_raw(progfd, &attr, pid, cpu, group_fd, 0);
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

/* Create a new ringbuf manager to manage ringbuf associated with
 * map_fd, associating it with callback sample_cb. */
void * bpf_new_ringbuf(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx) {
    return ring_buffer__new(map_fd, sample_cb, ctx, NULL);
}

/* Free the ringbuf manager rb and all ring buffers associated with it. */
void bpf_free_ringbuf(struct ring_buffer *rb) {
    ring_buffer__free(rb);
}

/* Add a new ring buffer associated with map_fd to the ring buffer manager rb,
 * associating it with callback sample_cb. */
int bpf_add_ringbuf(struct ring_buffer *rb, int map_fd,
                    ring_buffer_sample_fn sample_cb, void *ctx) {
    return ring_buffer__add(rb, map_fd, sample_cb, ctx);
}

/* Poll for available data and consume, if data is available.  Returns number
 * of records consumed, or a negative number if any callbacks returned an
 * error. */
int bpf_poll_ringbuf(struct ring_buffer *rb, int timeout_ms) {
    return ring_buffer__poll(rb, timeout_ms);
}

/* Consume available data _without_ polling. Good for use cases where low
 * latency is desired over performance impact.  Returns number of records
 * consumed, or a negative number if any callbacks returned an error. */
int bpf_consume_ringbuf(struct ring_buffer *rb) {
    return ring_buffer__consume(rb);
}

int bcc_iter_attach(int prog_fd, union bpf_iter_link_info *link_info,
                    uint32_t link_info_len)
{
    DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_create_opts);

    link_create_opts.iter_info = link_info;
    link_create_opts.iter_info_len = link_info_len;
    return bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, &link_create_opts);
}

int bcc_iter_create(int link_fd)
{
    return bpf_iter_create(link_fd);
}

int bcc_make_parent_dir(const char *path) {
  int   err = 0;
  char *dname, *dir;

  dname = strdup(path);
  if (dname == NULL)
    return -ENOMEM;

  dir = dirname(dname);
  if (mkdir(dir, 0700) && errno != EEXIST)
    err = -errno;

  free(dname);
  if (err)
    fprintf(stderr, "failed to mkdir %s: %s\n", path, strerror(-err));

  return err;
}

int bcc_check_bpffs_path(const char *path) {
  struct statfs st_fs;
  char  *dname, *dir;
  int    err = 0;

  if (path == NULL)
    return -EINVAL;

  dname = strdup(path);
  if (dname == NULL)
    return -ENOMEM;

  dir = dirname(dname);
  if (statfs(dir, &st_fs)) {
    err = -errno;
    fprintf(stderr, "failed to statfs %s: %s\n", path, strerror(-err));
  }

  free(dname);
  if (!err && st_fs.f_type != BPF_FS_MAGIC) {
    err = -EINVAL;
    fprintf(stderr, "specified path %s is not on BPF FS\n", path);
  }

  return err;
}
