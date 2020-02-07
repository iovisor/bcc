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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)

TEST_CASE("test sock map", "[sockmap]") {
  {
    const std::string BPF_PROGRAM = R"(
BPF_SOCKMAP(sk_map1, 10);
BPF_SOCKMAP(sk_map2, 10);
int test(struct bpf_sock_ops *skops)
{
  u32 key = 0, val = 0;

  sk_map2.update(&key, &val);
  sk_map2.delete(&key);
  sk_map2.sock_map_update(skops, &key, 0);

  return 0;
}
    )";

    // make sure program is loaded successfully
    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.code() == 0);

    // create a udp socket so we can do some map operations.
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(sockfd >= 0);

    auto sk_map = bpf.get_sockmap_table("sk_map1");
    int key = 0, val = sockfd;

    res = sk_map.remove_value(key);
    REQUIRE(res.code() != 0);

    // the socket must be TCP established socket.
    res = sk_map.update_value(key, val);
    REQUIRE(res.code() != 0);
  }
}

TEST_CASE("test sock hash", "[sockhash]") {
  {
    const std::string BPF_PROGRAM = R"(
BPF_SOCKHASH(sk_hash1, 10);
BPF_SOCKHASH(sk_hash2, 10);
int test(struct bpf_sock_ops *skops)
{
  u32 key = 0, val = 0;

  sk_hash2.update(&key, &val);
  sk_hash2.delete(&key);
  sk_hash2.sock_hash_update(skops, &key, 0);

  return 0;
}
    )";

    // make sure program is loaded successfully
    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.code() == 0);

    // create a udp socket so we can do some map operations.
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(sockfd >= 0);

    auto sk_hash = bpf.get_sockhash_table("sk_hash1");
    int key = 0, val = sockfd;

    res = sk_hash.remove_value(key);
    REQUIRE(res.code() != 0);

    // the socket must be TCP established socket.
    res = sk_hash.update_value(key, val);
    REQUIRE(res.code() != 0);
  }
}

#endif
