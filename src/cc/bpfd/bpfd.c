/*
 * BPFd (Berkeley Packet Filter daemon)
 *
 * Copyright (C) 2017 Joel Fernandes <agnel.joel@gmail.com>
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
#include <inttypes.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bcc_syms.h"
#include "bpfd.h"

#define LINEBUF_SIZE 2000000

#define DEFAULT_MAX_PID 32768

struct usym_cache {
  int pid;
  char *exe_path;
  void *cache;
};

int bpf_prog_load_handle(int type, char *name, char *bin_b64, int prog_len,
                         char *license, unsigned int kern_version) {
  int bin_len, ret;
  char *bin_buf = NULL;
  const struct bpf_insn *insns = NULL;

  bin_len = strlen(bin_b64);
  bin_buf = (char *)malloc(bin_len);

  if (!base64_decode(bin_b64, (unsigned char *)bin_buf, bin_len))
    return -1;

  insns = (const struct bpf_insn *)bin_buf;

  /* TODO: logging disabled for now, add mechanism in future */
  ret = bpf_prog_load((enum bpf_prog_type)type, name, insns, prog_len,
                      (const char *)license, kern_version, 0, NULL, 0);

  printf("bpf_prog_load: ret=%d\n", ret);
  return ret;
}

int get_trace_events(char *tracefs, char *category) {
  int res = 0;

  int buf_len = strlen(tracefs) + strlen("/events/") + strlen(category) + 1;
  char *tracef = (char *)malloc(buf_len);
  snprintf(tracef, buf_len, "%s/events/%s", tracefs, category);

  res = cat_dir(tracef, 1);

  free(tracef);
  return res;
}

int get_trace_events_categories(char *tracefs) {
  int res = 0;

  int buf_len = strlen(tracefs) + strlen("/events") + 1;
  char *tracef = (char *)malloc(buf_len);
  snprintf(tracef, buf_len, "%s/events", tracefs);

  res = cat_dir(tracef, 1);

  free(tracef);
  return res;
}

int bpf_remote_update_elem(int map_fd, char *kstr, int klen, char *lstr,
                           int llen, unsigned long flags) {
  int ret = -ENOMEM;
  void *kbin = NULL, *lbin = NULL;

  kbin = (void *)malloc(klen);
  if (!kbin)
    goto err_update;

  lbin = (void *)malloc(llen);
  if (!lbin)
    goto err_update;

  ret = -EINVAL;
  if (!base64_decode(kstr, kbin, klen))
    goto err_update;

  if (!base64_decode(lstr, lbin, llen))
    goto err_update;

  ret = bpf_update_elem(map_fd, kbin, lbin, flags);

err_update:
  if (kbin)
    free(kbin);
  if (lbin)
    free(lbin);
  return ret;
}

char *bpf_remote_lookup_elem(int map_fd, char *kstr, int klen, int llen) {
  void *lbin = NULL, *kbin = NULL;
  char *lstr = NULL, *rets = NULL;

  kbin = (void *)malloc(klen);
  if (!kbin)
    goto err_update;

  lbin = (void *)malloc(llen);
  if (!lbin)
    goto err_update;

  lstr = (char *)malloc(llen * 4);

  if (!lstr || !base64_decode(kstr, kbin, klen) ||
      (bpf_lookup_elem(map_fd, kbin, lbin) < 0))
    goto err_update;

  if (base64_encode(lbin, llen, lstr, llen * 4))
    rets = (char *)lstr;

err_update:
  if (lbin)
    free(lbin);
  if (kbin)
    free(kbin);
  if (!rets && lstr)
    free(lstr);
  return rets;
}

char *bpf_remote_get_first_key_dump_all(int map_fd, int klen, int llen) {
  void *kbin = NULL, *lbin = NULL, *next_kbin = NULL, *tmp = NULL;
  int ret, dump_buf_len = 4096, dump_used = 1;
  char *dump_buf = NULL, *kstr = NULL, *lstr = NULL, *rets = NULL;

/* length of base64 buffer with newlines considered */
#define KSTR_SIZE ((klen * 2) + 2)
#define LSTR_SIZE ((llen * 2) + 2)

  dump_buf = (char *)malloc(dump_buf_len);
  kbin = (void *)malloc(klen);
  lbin = (void *)malloc(llen);
  kstr = (char *)malloc(KSTR_SIZE);
  lstr = (char *)malloc(LSTR_SIZE);

  if (!dump_buf || !kbin || !lbin || !lstr || !kstr)
    goto err_get;

  if (bpf_get_first_key(map_fd, kbin, klen) < 0)
    goto get_done;

  dump_buf[0] = 0;

  do {
    next_kbin = (void *)malloc(klen);
    if (!next_kbin)
      goto err_get;

    if (bpf_lookup_elem(map_fd, kbin, lbin) < 0)
      goto err_get;

    if (!base64_encode(kbin, klen, kstr, KSTR_SIZE) ||
        !base64_encode(lbin, llen, lstr, LSTR_SIZE))
      goto err_get;

    if (dump_buf_len - dump_used < (LSTR_SIZE + KSTR_SIZE)) {
      dump_buf_len *= 2;
      dump_buf = (char *)realloc(dump_buf, dump_buf_len);
    }

    strcat(kstr, "\n");
    strcat(lstr, "\n");
    strncat(dump_buf, kstr, dump_buf_len);
    strncat(dump_buf, lstr, dump_buf_len);
    dump_used += (KSTR_SIZE + LSTR_SIZE);

    ret = bpf_get_next_key(map_fd, kbin, next_kbin);

    tmp = kbin;
    kbin = next_kbin;
    next_kbin = NULL;
    free(tmp);
  } while (ret >= 0);

  rets = dump_buf;
  goto get_done;

err_get:
  printf("bpf_remote_get_first_key_dump_all: error condition\n");
  if (dump_buf)
    free(dump_buf);

get_done:
  if (kbin)
    free(kbin);
  if (lbin)
    free(lbin);
  if (kstr)
    free(kstr);
  if (lstr)
    free(lstr);
  if (next_kbin)
    free(next_kbin);
  return rets;
}

char *bpf_remote_get_first_key(int map_fd, int klen) {
  void *kbin = NULL;
  char *kstr = NULL, *rets = NULL;

  kbin = (void *)malloc(klen);
  if (!kbin)
    goto err_get;

  kstr = (char *)malloc(klen * 4);
  if (!kstr || bpf_get_first_key(map_fd, kbin, klen) < 0)
    goto err_get;

  if (base64_encode(kbin, klen, kstr, klen * 4))
    rets = kstr;

err_get:
  if (kbin)
    free(kbin);
  if (!rets && kstr)
    free(kstr);
  return rets;
}

char *bpf_remote_get_next_key(int map_fd, char *kstr, int klen) {
  void *kbin = NULL, *next_kbin = NULL;
  char *next_kstr = NULL, *rets = NULL;

  kbin = (void *)malloc(klen);
  if (!kbin)
    goto err_update;

  next_kbin = (void *)malloc(klen);
  if (!next_kbin)
    goto err_update;

  next_kstr = (char *)malloc(klen * 4);

  if (!next_kstr || !base64_decode(kstr, kbin, klen) ||
      (bpf_get_next_key(map_fd, kbin, next_kbin) < 0))
    goto err_update;

  if (base64_encode(next_kbin, klen, next_kstr, klen * 4))
    rets = (char *)next_kstr;

err_update:
  if (kbin)
    free(kbin);
  if (next_kbin)
    free(next_kbin);
  if (!rets && next_kstr)
    free(next_kstr);
  return rets;
}

int bpf_remote_delete_elem(int map_fd, char *kstr, int klen) {
  void *kbin = NULL;
  int ret = -ENOMEM;

  kbin = (void *)malloc(klen);
  if (!kbin)
    goto err_update;

  ret = -1;
  if (!base64_decode(kstr, kbin, klen))
    goto err_update;

  ret = bpf_delete_elem(map_fd, kbin);

err_update:
  if (kbin)
    free(kbin);
  return ret;
}

/*
 * Clear a map by iterating over keys.
 * Return delete error code if any deletes or allocs fail
 * else return how many keys were iterated and deleted.
 */
int bpf_clear_map(int map_fd, int klen) {
  void *kbin = NULL, *next_kbin = NULL, *tmp = NULL;
  int count = 0, ret = -ENOMEM;

  kbin = (void *)malloc(klen);
  if (!kbin)
    goto err_clear;

  if (bpf_get_first_key(map_fd, kbin, klen) < 0) {
    ret = 0;
    goto err_clear;
  }

  do {
    next_kbin = (void *)malloc(klen);
    if (!next_kbin) {
      ret = -ENOMEM;
      goto err_clear;
    }

    ret = bpf_delete_elem(map_fd, kbin);
    if (ret < 0)
      goto err_clear;
    count++;

    ret = bpf_get_next_key(map_fd, kbin, next_kbin);

    tmp = kbin;
    kbin = next_kbin;
    next_kbin = NULL;
    free(tmp);
  } while (ret >= 0);

  ret = count;

err_clear:
  if (kbin)
    free(kbin);
  if (next_kbin)
    free(next_kbin);
  return ret;
}

char *get_pid_exe(int pid) {
  const int PATHBUF_SIZE = 4096;

  char *exe_path = (char *)malloc(PATHBUF_SIZE);
  char exe_link[PATHBUF_SIZE];
  int num_chars_read = 0;

  snprintf(exe_link, PATHBUF_SIZE, "/proc/%d/exe", pid);
  num_chars_read = readlink(exe_link, exe_path, PATHBUF_SIZE);
  if (num_chars_read < 0)
    num_chars_read = 0;
  exe_path[num_chars_read] = '\0';
  return exe_path;
}

struct usym_cache *get_or_set_usym_cache(int pid,
                                         struct usym_cache *usym_caches[]) {
  struct usym_cache *usym_cache = usym_caches[pid % DEFAULT_MAX_PID];

  char *exe_path = get_pid_exe(pid);
  if (!usym_cache || usym_cache->pid != pid ||
      strcmp(usym_cache->exe_path, exe_path)) {
    if (!usym_cache) {
      usym_cache = (struct usym_cache *)malloc(sizeof(struct usym_cache));
    } else {
      free(usym_cache->exe_path);
      bcc_free_symcache(usym_cache->cache, usym_cache->pid);
    }

    usym_cache->pid = pid;
    usym_cache->exe_path = exe_path;
    usym_cache->cache = bcc_symcache_new(pid, NULL);

    usym_caches[pid % DEFAULT_MAX_PID] = usym_cache;
  } else {
    free(exe_path);
  }

  return usym_cache;
}

void free_usym_caches(struct usym_cache **usym_caches) {
  int i;
  for (i = 0; i < DEFAULT_MAX_PID; i++) {
    if (usym_caches[i]) {
      free(usym_caches[i]->exe_path);
      bcc_free_symcache(usym_caches[i]->cache, usym_caches[i]->pid);

      free(usym_caches[i]);
    }
  }

  free(usym_caches);
}

int main(int argc, char **argv) {
  struct user_input *in = NULL;
  char line_buf[LINEBUF_SIZE];
  int arg_index = 0;
  void *ksym_cache = NULL;
  struct usym_cache **usym_caches = (struct usym_cache **)calloc(
      DEFAULT_MAX_PID, sizeof(struct usym_cache *));

  printf("STARTED_BPFD\n");

  while (fgets(line_buf, LINEBUF_SIZE, stdin)) {
    line_buf[strcspn(line_buf, "\n")] = '\0';

    /* Empty input */
    if (!strlen(line_buf))
      continue;

    in = parse_user_input(line_buf);
    arg_index = 0;

    if (!strcmp(in->cmd, "exit")) {
      free_user_input(in);
      in = NULL;
      break;
    }

    printf("START_BPFD_OUTPUT\n");
    fflush(stdout);

    if (!strcmp(in->cmd, "GET_KALLSYMS")) {
      if (cat_file("/proc/kallsyms") < 0)
        goto invalid_command;

    } else if (!strcmp(in->cmd, "GET_KPROBES_BLACKLIST")) {
      char *tracefs;

      PARSE_STR(tracefs);

      if (cat_tracefs_file(tracefs, "../kprobes/blacklist") < 0)
        goto invalid_command;

    } else if (!strcmp(in->cmd, "GET_TRACE_EVENTS_CATEGORIES")) {
      char *tracefs;

      PARSE_STR(tracefs);

      if (get_trace_events_categories(tracefs) < 0)
        goto invalid_command;

    } else if (!strcmp(in->cmd, "GET_TRACE_EVENTS")) {
      char *tracefs, *category;

      PARSE_STR(tracefs);
      PARSE_STR(category);

      if (get_trace_events(tracefs, category) < 0)
        goto invalid_command;

    } else if (!strcmp(in->cmd, "COMM_FOR_PID")) {
      int pid;

      PARSE_INT(pid);

      if (cat_comm_file(pid) < 0)
        goto invalid_command;

    } else if (!strcmp(in->cmd, "BPF_PROG_LOAD")) {
      int prog_len, type;
      char *license, *bin_data, *name;
      unsigned int kern_version;

      PARSE_INT(type);
      PARSE_STR(name);
      PARSE_INT(prog_len);
      PARSE_STR(license);
      PARSE_UINT(kern_version);
      PARSE_STR(bin_data);

      if (!strcmp(name, "__none__"))
        name = NULL;
      bpf_prog_load_handle(type, name, bin_data, prog_len, license,
                           kern_version);

    } else if (!strcmp(in->cmd, "BPF_ATTACH_KPROBE")) {
      int ret, prog_fd, type;
      char *ev_name, *fn_name;

      PARSE_INT(prog_fd);
      PARSE_INT(type);
      PARSE_STR(ev_name);
      PARSE_STR(fn_name);

      ret = bpf_attach_kprobe(prog_fd, type, ev_name, fn_name);
      printf("bpf_attach_kprobe: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_DETACH_KPROBE")) {
      int ret;
      char *evname;

      PARSE_STR(evname);
      ret = bpf_detach_kprobe(evname);
      printf("bpf_detach_kprobe: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_ATTACH_UPROBE")) {
      int ret, prog_fd, type, pid;
      char *ev_name, *binary_path;
      uint64_t offset;

      PARSE_INT(prog_fd);
      PARSE_INT(type);
      PARSE_STR(ev_name);
      PARSE_STR(binary_path);
      PARSE_UINT64(offset);
      PARSE_INT(pid);

      ret = bpf_attach_uprobe(prog_fd, type, ev_name, binary_path, offset, pid);
      printf("bpf_attach_uprobe: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_DETACH_UPROBE")) {
      int ret;
      char *evname;

      PARSE_STR(evname);
      ret = bpf_detach_uprobe(evname);
      printf("bpf_detach_uprobe: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_ATTACH_TRACEPOINT")) {
      int ret, prog_fd;
      char *tpname, *category;

      PARSE_INT(prog_fd);
      PARSE_STR(category);
      PARSE_STR(tpname);

      ret = bpf_attach_tracepoint(prog_fd, category, tpname);
      printf("bpf_attach_tracepoint: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_DETACH_TRACEPOINT")) {
      int ret;
      char *tpname, *category;

      PARSE_STR(category);
      PARSE_STR(tpname);

      ret = bpf_detach_tracepoint(category, tpname);
      printf("bpf_detach_tracepoint: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_ATTACH_PERF_EVENT")) {
      int ret, progfd, pid, cpu, group_fd;
      uint32_t ev_type, ev_config;
      uint64_t sample_period, sample_freq;

      PARSE_INT(progfd);
      PARSE_UINT32(ev_type);
      PARSE_UINT32(ev_config);
      PARSE_UINT64(sample_period);
      PARSE_UINT64(sample_freq);
      PARSE_INT(pid);
      PARSE_INT(cpu);
      PARSE_INT(group_fd);

      ret = bpf_attach_perf_event(progfd, ev_type, ev_config, sample_period,
                                  sample_freq, pid, cpu, group_fd);
      printf("bpf_attach_perf_event: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_CLOSE_PERF_EVENT_FD")) {
      int fd, ret;

      PARSE_INT(fd);
      ret = bpf_close_perf_event_fd(fd);
      printf("bpf_close_perf_event_fd: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_CREATE_MAP")) {
      int ret, type, key_size, value_size, max_entries, map_flags;
      char *name;

      PARSE_INT(type);
      PARSE_STR(name);
      PARSE_INT(key_size);
      PARSE_INT(value_size);
      PARSE_INT(max_entries);
      PARSE_INT(map_flags);

      if (!strcmp(name, "__none__"))
        name = NULL;
      ret = bpf_create_map((enum bpf_map_type)type, name, key_size, value_size,
                           max_entries, map_flags);
      printf("bpf_create_map: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_OPEN_PERF_BUFFER")) {
      int pid, cpu, page_cnt, ret;

      PARSE_INT(pid);
      PARSE_INT(cpu);
      PARSE_INT(page_cnt);

      ret = bpf_remote_open_perf_buffer(pid, cpu, page_cnt);
      printf("bpf_open_perf_buffer: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_UPDATE_ELEM")) {
      int map_fd, klen, llen, ret;
      unsigned long long flags;
      char *kstr, *lstr;

      PARSE_INT(map_fd);
      PARSE_STR(kstr);
      PARSE_INT(klen);
      PARSE_STR(lstr);
      PARSE_INT(llen);
      PARSE_ULL(flags);

      ret = bpf_remote_update_elem(map_fd, kstr, klen, lstr, llen, flags);
      printf("bpf_update_elem: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_LOOKUP_ELEM")) {
      int map_fd, klen, llen;
      char *kstr, *lstr;

      PARSE_INT(map_fd);
      PARSE_STR(kstr);
      PARSE_INT(klen);
      PARSE_INT(llen);

      lstr = bpf_remote_lookup_elem(map_fd, kstr, klen, llen);
      if (!lstr)
        printf("bpf_lookup_elem: ret=%d\n", -1);
      else
        printf("%s\n", lstr);
      if (lstr)
        free(lstr);

    } else if (!strcmp(in->cmd, "BPF_GET_FIRST_KEY")) {
      int map_fd, klen, llen, dump_all;
      char *kstr;

      PARSE_INT(map_fd);
      PARSE_INT(klen);
      PARSE_INT(llen);
      PARSE_INT(dump_all);

      if (dump_all)
        kstr = bpf_remote_get_first_key_dump_all(map_fd, klen, llen);
      else
        kstr = bpf_remote_get_first_key(map_fd, klen);

      if (!kstr)
        printf("bpf_get_first_key: ret=%d\n", -1);
      else
        printf("%s\n", kstr);
      if (kstr)
        free(kstr);

    } else if (!strcmp(in->cmd, "BPF_GET_NEXT_KEY")) {
      int map_fd, klen;
      char *kstr, *next_kstr;

      PARSE_INT(map_fd);
      PARSE_STR(kstr);
      PARSE_INT(klen);

      next_kstr = bpf_remote_get_next_key(map_fd, kstr, klen);
      if (!next_kstr)
        printf("bpf_get_next_key: ret=%d\n", -1);
      else
        printf("%s\n", next_kstr);
      if (next_kstr)
        free(next_kstr);

    } else if (!strcmp(in->cmd, "BPF_DELETE_ELEM")) {
      int map_fd, klen, ret;
      char *kstr;

      PARSE_INT(map_fd);
      PARSE_STR(kstr);
      PARSE_INT(klen);

      ret = bpf_remote_delete_elem(map_fd, kstr, klen);
      printf("bpf_delete_elem: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "BPF_CLEAR_MAP")) {
      int map_fd, klen, ret;

      PARSE_INT(map_fd);
      PARSE_INT(klen);

      ret = bpf_clear_map(map_fd, klen);
      printf("bpf_clear_map: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "PERF_READER_POLL")) {
      int len, *fds, i, timeout, ret;

      PARSE_INT(timeout);
      PARSE_INT(len);

      fds = (void *)malloc(len);
      if (!fds)
        printf("perf_reader_poll: ret=%d\n", -ENOMEM);

      for (i = 0; i < len; i++) {
        PARSE_INT(fds[i]);
      }

      ret = remote_perf_reader_poll(fds, len, timeout);
      if (ret < 0)
        printf("perf_reader_poll: ret=%d\n", ret);

    } else if (!strcmp(in->cmd, "GET_KSYM_NAME")) {
      int ret;
      uint64_t addr;
      struct bcc_symbol sym;

      PARSE_UINT64(addr);

      if (!ksym_cache)
        ksym_cache = bcc_symcache_new(-1, NULL);

      ret = bcc_symcache_resolve_no_demangle(ksym_cache, addr, &sym);
      printf("GET_KSYM_NAME: ret=%d\n", ret);
      if (!ret)
        printf("%s;%" PRIu64 ";%s\n", sym.name, sym.offset, sym.module);

    } else if (!strcmp(in->cmd, "GET_KSYM_ADDR")) {
      int ret;
      char *name;
      uint64_t addr;

      PARSE_STR(name);

      if (!ksym_cache)
        ksym_cache = bcc_symcache_new(-1, NULL);

      ret = bcc_symcache_resolve_name(ksym_cache, NULL, name, &addr);
      printf("GET_KSYM_ADDR: ret=%d\n", ret);
      if (!ret)
        printf("%" PRIu64 "\n", addr);

    } else if (!strcmp(in->cmd, "GET_USYM_NAME")) {
      int ret, pid, demangle;
      uint64_t addr;
      struct bcc_symbol sym;
      const char *name;
      struct usym_cache *usym_cache = NULL;

      PARSE_INT(pid);
      PARSE_UINT64(addr);
      PARSE_INT(demangle);

      usym_cache = get_or_set_usym_cache(pid, usym_caches);

      if (demangle)
        ret = bcc_symcache_resolve(usym_cache->cache, addr, &sym);
      else
        ret = bcc_symcache_resolve_no_demangle(usym_cache->cache, addr, &sym);

      printf("GET_USYM_NAME: ret=%d\n", ret);
      if (!ret) {
        if (demangle)
          name = sym.demangle_name;
        else
          name = sym.name;
        printf("%s;%" PRIu64 ";%s\n", name, sym.offset, sym.module);
      }
      bcc_symbol_free_demangle_name(&sym);

    } else if (!strcmp(in->cmd, "GET_USYM_ADDR")) {
      int ret, pid;
      char *name;
      char *module;
      uint64_t addr;
      struct usym_cache *usym_cache = NULL;

      PARSE_INT(pid);
      PARSE_STR(name);
      PARSE_STR(module);

      usym_cache = get_or_set_usym_cache(pid, usym_caches);

      ret = bcc_symcache_resolve_name(usym_cache->cache, module, name, &addr);
      printf("GET_USYM_ADDR: ret=%d\n", ret);
      if (!ret)
        printf("%" PRIu64 "\n", addr);

    } else {
    invalid_command:
      printf("Command not recognized\n");
    }

    printf("END_BPFD_OUTPUT\n");
    fflush(stdout);

    free_user_input(in);
    in = NULL;
  }
  free_usym_caches(usym_caches);
  return 0;
}
