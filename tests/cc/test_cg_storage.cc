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
#include <vector>

#include "BPF.h"
#include "catch.hpp"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

TEST_CASE("test cgroup storage", "[cgroup_storage]") {
  {
    const std::string BPF_PROGRAM = R"(
BPF_CGROUP_STORAGE(cg_storage1, int);
BPF_CGROUP_STORAGE(cg_storage2, int);
int test(struct bpf_sock_ops *skops)
{
  struct bpf_cgroup_storage_key key = {0};
  u32 val = 0;

  cg_storage2.lookup(&key);
  cg_storage2.update(&key, &val);
  cg_storage2.get_local_storage(0);

  return 0;
}
    )";

    // make sure program is loaded successfully
    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.code() == 0);

    auto cg_storage = bpf.get_cg_storage_table<int>("cg_storage1");
    struct bpf_cgroup_storage_key key = {0};
    int val;

    // all the following lookup/update will fail since
    // cgroup local storage only created during prog attachment time.
    res = cg_storage.get_value(key, val);
    REQUIRE(res.code() != 0);

    res = cg_storage.update_value(key, val);
    REQUIRE(res.code() != 0);
  }
}

TEST_CASE("test percpu cgroup storage", "[percpu_cgroup_storage]") {
  {
    const std::string BPF_PROGRAM = R"(
BPF_PERCPU_CGROUP_STORAGE(cg_storage1, long long);
BPF_PERCPU_CGROUP_STORAGE(cg_storage2, long long);
int test(struct bpf_sock_ops *skops)
{
  struct bpf_cgroup_storage_key key = {0};
  long long val = 0;

  cg_storage2.lookup(&key);
  cg_storage2.update(&key, &val);
  cg_storage2.get_local_storage(0);

  return 0;
}
    )";

    // make sure program is loaded successfully
    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.code() == 0);

    auto cg_storage = bpf.get_percpu_cg_storage_table<long long>("cg_storage1");
    struct bpf_cgroup_storage_key key = {0};
    std::vector<long long> val(ebpf::BPFTable::get_possible_cpu_count());

    // all the following lookup/update will fail since
    // cgroup local storage only created during prog attachment time.
    res = cg_storage.get_value(key, val);
    REQUIRE(res.code() != 0);

    res = cg_storage.update_value(key, val);
    REQUIRE(res.code() != 0);
  }
}

#endif
