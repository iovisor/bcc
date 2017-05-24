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

const std::string BPF_PROGRAM1 = R"(
BPF_TABLE_SHARED("array", int, int, mysharedtable, 1024);
)";

const std::string BPF_PROGRAM2 = R"(
BPF_TABLE("extern", int, int, mysharedtable, 1024);
)";

TEST_CASE("test shared table", "[shared_table]") {
  // deploy 4 ebpf programs: 1a and 1b are in ns1, 2a and 2b in ns2
  ebpf::BPF bpf1a(0, nullptr, "ns1");
  ebpf::BPF bpf1b(0, nullptr, "ns1");
  ebpf::BPF bpf2a(0, nullptr, "ns2");
  ebpf::BPF bpf2b(0, nullptr, "ns2");

  ebpf::StatusTuple res(0);

  res = bpf1a.init(BPF_PROGRAM1);
  REQUIRE(res.code() == 0);

  res = bpf1b.init(BPF_PROGRAM2);
  REQUIRE(res.code() == 0);

  res = bpf2a.init(BPF_PROGRAM1);
  REQUIRE(res.code() == 0);

  res = bpf2b.init(BPF_PROGRAM2);
  REQUIRE(res.code() == 0);

  // get references to all tables
  ebpf::BPFArrayTable<int> t1a = bpf1a.get_array_table<int>("mysharedtable");
  ebpf::BPFArrayTable<int> t1b = bpf1b.get_array_table<int>("mysharedtable");
  ebpf::BPFArrayTable<int> t2a = bpf2a.get_array_table<int>("mysharedtable");
  ebpf::BPFArrayTable<int> t2b = bpf2b.get_array_table<int>("mysharedtable");

  // test that tables within the same ns are shared
  int v1, v2, v3;
  res = t1a.update_value(13, 42);
  REQUIRE(res.code() == 0);

  res = t1b.get_value(13, v1);
  REQUIRE(res.code() == 0);
  REQUIRE(v1 == 42);

  // test that tables are isolated within different ns
  res = t2a.update_value(13, 69);
  REQUIRE(res.code() == 0);

  res = t2b.get_value(13, v2);
  REQUIRE(res.code() == 0);
  REQUIRE(v2 == 69);

  res = t1b.get_value(13, v3);
  REQUIRE(res.code() == 0);
  REQUIRE(v3 == 42);  // value should still be 42
}
