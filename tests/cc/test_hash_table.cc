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
  }
}
