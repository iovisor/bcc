/*
 * Copyright (c) 2017 Politecnico di Torino
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

#include "BPF.h"
#include <linux/version.h>

#include "catch.hpp"

TEST_CASE("test hash table", "[hash_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_TABLE("hash", int, int, myhash, 1024);
    BPF_TABLE("array", int, int, myarray, 1024);
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFHashTable<int, int> t = bpf.get_hash_table<int, int>("myhash");

  SECTION("bad table type") {
    // try to get table of wrong type
    auto f1 = [&](){
      bpf.get_hash_table<int, int>("myarray");
    };

    REQUIRE_THROWS(f1());
  }

  SECTION("standard methods") {
    int k, v1, v2;
    k = 1;
    v1 = 42;
    // create new element
    res = t.update_value(k, v1);
    REQUIRE(res.code() == 0);
    res = t.get_value(k, v2);
    REQUIRE(res.code() == 0);
    REQUIRE(v2 == 42);

    // update existing element
    v1 = 69;
    res = t.update_value(k, v1);
    REQUIRE(res.code() == 0);
    res = t.get_value(k, v2);
    REQUIRE(res.code() == 0);
    REQUIRE(v2 == 69);

    // remove existing element
    res = t.remove_value(k);
    REQUIRE(res.code() == 0);

    // remove non existing element
    res = t.remove_value(k);
    REQUIRE(res.code() != 0);

    // get non existing element
    res = t.get_value(k, v2);
    REQUIRE(res.code() != 0);
  }

  SECTION("walk table") {
    for (int i = 1; i <= 10; i++) {
      res = t.update_value(i * 3, i);
      REQUIRE(res.code() == 0);
    }
    auto offline = t.get_table_offline();
    REQUIRE(offline.size() == 10);
    for (const auto &pair : offline) {
      REQUIRE(pair.first % 3 == 0);
      REQUIRE(pair.first / 3 == pair.second);
    }

    // clear table
    t.clear_table_non_atomic();
    REQUIRE(t.get_table_offline().size() == 0);
  }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
TEST_CASE("percpu hash table", "[percpu_hash_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_TABLE("percpu_hash", int, u64, myhash, 128);
    BPF_TABLE("percpu_array", int, u64, myarray, 64);
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFPercpuHashTable<int, uint64_t> t =
    bpf.get_percpu_hash_table<int, uint64_t>("myhash");
  size_t ncpus = ebpf::BPFTable::get_possible_cpu_count();

  SECTION("bad table type") {
    // try to get table of wrong type
    auto f1 = [&](){
      bpf.get_percpu_hash_table<int, uint64_t>("myarray");
    };

    REQUIRE_THROWS(f1());
  }

  SECTION("standard methods") {
    int k;
    std::vector<uint64_t> v1(ncpus);
    std::vector<uint64_t> v2;

    for (size_t j = 0; j < ncpus; j++) {
      v1[j] = 42 * j;
    }

    k = 1;

    // create new element
    res = t.update_value(k, v1);
    REQUIRE(res.code() == 0);
    res = t.get_value(k, v2);
    REQUIRE(res.code() == 0);
    for (size_t j = 0; j < ncpus; j++) {
      REQUIRE(v2.at(j) == 42 * j);
    }

    // update existing element
    for (size_t j = 0; j < ncpus; j++) {
      v1[j] = 69 * j;
    }
    res = t.update_value(k, v1);
    REQUIRE(res.code() == 0);
    res = t.get_value(k, v2);
    REQUIRE(res.code() == 0);
    for (size_t j = 0; j < ncpus; j++) {
      REQUIRE(v2.at(j) == 69 * j);
    }

    // remove existing element
    res = t.remove_value(k);
    REQUIRE(res.code() == 0);

    // remove non existing element
    res = t.remove_value(k);
    REQUIRE(res.code() != 0);

    // get non existing element
    res = t.get_value(k, v2);
    REQUIRE(res.code() != 0);
  }

  SECTION("walk table") {
    std::vector<uint64_t> v(ncpus);

    for (int k = 3; k <= 30; k+=3) {
      for (size_t cpu = 0; cpu < ncpus; cpu++) {
        v[cpu] = k * cpu;
      }
      res = t.update_value(k, v);
      REQUIRE(res.code() == 0);
    }

    // get whole table
    auto offline = t.get_table_offline();
    REQUIRE(offline.size() == 10);
    for (int i = 0; i < 10; i++) {
      // check the key
      REQUIRE(offline.at(i).first % 3 == 0);

      // check value
      for (size_t cpu = 0; cpu < ncpus; cpu++) {
        REQUIRE(offline.at(i).second.at(cpu) == cpu * offline.at(i).first);
      }
    }

    // clear table
    t.clear_table_non_atomic();
    REQUIRE(t.get_table_offline().size() == 0);
  }
}
#endif
