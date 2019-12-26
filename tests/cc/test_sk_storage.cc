/*
 * Copyright (c) 2020 Facebook, Inc.
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

#include <linux/version.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>

#include "BPF.h"
#include "catch.hpp"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)

TEST_CASE("test sk_storage map", "[sk_storage]") {
  {
    const std::string BPF_PROGRAM = R"(
BPF_SK_STORAGE(sk_pkt_cnt, __u64);

int test(struct __sk_buff *skb) {
  __u64 cnt = 0, *cnt_out;
  struct bpf_sock *sk;

  sk = skb->sk;
  if (!sk)
    return 1;

  sk = bpf_sk_fullsock(sk);
  if (!sk)
    return 1;

  cnt_out = sk_pkt_cnt.sk_storage_get(sk, &cnt, BPF_SK_STORAGE_GET_F_CREATE);
  if (!cnt_out)
    return 1;

  (*cnt_out)++;
  return 1;
}
    )";

    // make sure program is loaded successfully
    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.code() == 0);
    int prog_fd;
    res = bpf.load_func("test", BPF_PROG_TYPE_CGROUP_SKB, prog_fd);
    REQUIRE(res.code() == 0);

    // create a udp socket so we can do some map operations.
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(sockfd >= 0);

    auto sk_table = bpf.get_sk_storage_table<unsigned long long>("sk_pkt_cnt");
    unsigned long long v = 0, v1 = 10;

    // no sk_storage for the table yet.
    res = sk_table.get_value(sockfd, v);
    REQUIRE(res.code() != 0);

    // nothing to remove yet.
    res = sk_table.remove_value(sockfd);
    REQUIRE(res.code() != 0);

    // update the table with a certain value.
    res = sk_table.update_value(sockfd, v1);
    REQUIRE(res.code() == 0);

    // get_value should be successful now.
    res = sk_table.get_value(sockfd, v);
    REQUIRE(res.code() == 0);
    REQUIRE(v == 10);

    // remove the sk_storage.
    res = sk_table.remove_value(sockfd);
    REQUIRE(res.code() == 0);
  }
}

#endif
