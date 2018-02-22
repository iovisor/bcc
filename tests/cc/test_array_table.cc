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

#include <random>
#include <iostream>

TEST_CASE("test array table", "[array_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_TABLE("hash", int, int, myhash, 128);
    BPF_TABLE("array", int, int, myarray, 128);
  )";

  // turn off the rw_engine
  ebpf::BPF bpf(0, nullptr, false);
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFArrayTable<int> t = bpf.get_array_table<int>("myarray");

  SECTION("bad table type") {
    // try to get table of wrong type
    auto f1 = [&](){
      bpf.get_array_table<int>("myhash");
    };

    REQUIRE_THROWS(f1());
  }

  SECTION("standard methods") {
    int i, v1, v2;
    i = 1;
    v1 = 42;
    // update element
    res = t.update_value(i, v1);
    REQUIRE(res.code() == 0);
    res = t.get_value(i, v2);
    REQUIRE(res.code() == 0);
    REQUIRE(v2 == 42);

    // update another element
    i = 2;
    v1 = 69;
    res = t.update_value(i, v1);
    REQUIRE(res.code() == 0);
    res = t.get_value(i, v2);
    REQUIRE(res.code() == 0);
    REQUIRE(v2 == 69);

    // get non existing element
    i = 1024;
    res = t.get_value(i, v2);
    REQUIRE(res.code() != 0);
  }

  SECTION("full table") {
    // random number generator
    std::mt19937 rng;
    rng.seed(std::random_device()());
    std::uniform_int_distribution<int> dist;

    std::vector<int> localtable(128);

    for(int i = 0; i < 128; i++) {
      int v = dist(rng);

      res = t.update_value(i, v);
      REQUIRE(res.code() == 0);

      // save it in the local table to compare later on
      localtable[i] = v;
    }

    std::vector<int> offlinetable = t.get_table_offline();
    REQUIRE(localtable == offlinetable);
  }
}
