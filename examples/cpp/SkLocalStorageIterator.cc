/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * Usage:
 *   ./SkLocalStorageIterator
 *
 * BPF socket local storage map iterator supported is added in 5.9.
 * But since it takes locks during iterating, it may have performance
 * implication if in parallel some other bpf program or user space
 * is doing map update/delete for sockets in the same bucket. The issue
 * is fixed in 5.10 with the following patch which uses rcu lock instead:
 *   https://lore.kernel.org/bpf/20200916224645.720172-1-yhs@fb.com
 *
 * This example shows how to dump local storage data from all sockets
 * associated with one socket local storage map.
 * An example output likes below:
 *   family  prot    val
 *   2       17      20
 *   2       17      10
 */

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <net/if.h>

#include "bcc_version.h"
#include "BPF.h"

const std::string BPF_PROGRAM = R"(

#include <linux/bpf.h>
#include <linux/seq_file.h>
#include <net/sock.h>

/* the structure is defined in .c file, so explicitly define
 * the structure here.
 */
struct bpf_iter__bpf_sk_storage_map {
  union {
    struct bpf_iter_meta *meta;
  };
  union {
    struct bpf_map *map;
  };
  union {
    struct sock *sk;
  };
  union {
    void *value;
  };
};

BPF_SK_STORAGE(sk_data_map, __u64);

struct info_t {
  __u32 family;
  __u32 protocol;
  __u64 val;
};

BPF_ITER(bpf_sk_storage_map) {
  struct seq_file *seq = ctx->meta->seq;
  struct sock *sk = ctx->sk;
  __u64 *val = ctx->value;
  struct info_t info = {};

  if (sk == (void *)0 || val == (void *)0)
    return 0;

  info.family = sk->sk_family;
  info.protocol = sk->sk_protocol;
  info.val = *val;
  bpf_seq_write(seq, &info, sizeof(info));

  return 0;
}
)";

struct info_t {
  unsigned family;
  unsigned protocol;
  unsigned long long val;
};

int main() {
  ebpf::BPF bpf;
  auto res = bpf.init(BPF_PROGRAM);
  if (res.code() != 0) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  // create two sockets
  int sockfd1 = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd1 < 0) {
    std::cerr << "socket1 create failure: " << sockfd1 << std::endl;
    return 1;
  }

  int sockfd2 = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd2 < 0) {
    std::cerr << "socket2 create failure: " << sockfd2 << std::endl;
    close(sockfd1);
    return 1;
  }

  unsigned long long v1 = 10, v2 = 20;
  auto sk_table = bpf.get_sk_storage_table<unsigned long long>("sk_data_map");

  res = sk_table.update_value(sockfd1, v1);
  if (res.code() != 0) {
    std::cerr << "sk_data_map sockfd1 update failure: " << res.msg() << std::endl;
    close(sockfd2);
    close(sockfd1);
    return 1;
  }

  res = sk_table.update_value(sockfd2, v2);
  if (res.code() != 0) {
    std::cerr << "sk_data_map sockfd2 update failure: " << res.msg() << std::endl;
    close(sockfd2);
    close(sockfd1);
    return 1;
  }

  int prog_fd;
  res = bpf.load_func("bpf_iter__bpf_sk_storage_map", BPF_PROG_TYPE_TRACING, prog_fd);
  if (res.code() != 0) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  union bpf_iter_link_info link_info = {};
  link_info.map.map_fd = sk_table.get_fd();
  int link_fd = bcc_iter_attach(prog_fd, &link_info, sizeof(union bpf_iter_link_info));
  if (link_fd < 0) {
    std::cerr << "bcc_iter_attach failed: " << link_fd << std::endl;
    close(sockfd2);
    close(sockfd1);
    return 1;
  }

  int iter_fd = bcc_iter_create(link_fd);
  if (iter_fd < 0) {
    std::cerr << "bcc_iter_create failed: " << iter_fd << std::endl;
    close(link_fd);
    close(sockfd2);
    close(sockfd1);
    return 1;
  }

  // Header.
  printf("family\tprot\tval\n");

  struct info_t info[20];
  int len, leftover = 0, info_size = 20 * sizeof(struct info_t);
  while ((len = read(iter_fd, (char *)info + leftover, info_size - leftover))) {
    if (len < 0) {
      if (len == -EAGAIN)
        continue;
      std::cerr << "read failed: " << len << std::endl;
      break;
    }

    int num_info = len / sizeof(struct info_t);
    for (int i = 0; i < num_info; i++) {
      printf("%d\t%d\t%lld\n", info[i].family, info[i].protocol, info[i].val);
    }

    leftover = len % sizeof(struct info_t);
    if (num_info > 0)
      memcpy(info, (void *)&info[num_info], leftover);
  }

  close(iter_fd);
  close(link_fd);
  close(sockfd2);
  close(sockfd1);
  return 0;
}
