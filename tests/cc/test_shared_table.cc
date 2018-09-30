/*
 * Copyright (c) 2018 Politecnico di Torino
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
  // deploy 4 ebpf programs: _ns1_a and _ns1_b are in ns1, _ns2_a and _ns2_b in ns2
  ebpf::BPF bpf_ns1_a(0, nullptr, false, "ns1");
  ebpf::BPF bpf_ns1_b(0, nullptr, false, "ns1");
  ebpf::BPF bpf_ns2_a(0, nullptr, false, "ns2");
  ebpf::BPF bpf_ns2_b(0, nullptr, false, "ns2");

  ebpf::StatusTuple res(0);

  res = bpf_ns1_a.init(BPF_PROGRAM1);
  REQUIRE(res.code() == 0);

  res = bpf_ns1_b.init(BPF_PROGRAM2);
  REQUIRE(res.code() == 0);

  res = bpf_ns2_a.init(BPF_PROGRAM1);
  REQUIRE(res.code() == 0);

  res = bpf_ns2_b.init(BPF_PROGRAM2);
  REQUIRE(res.code() == 0);

  // get references to all tables
  ebpf::BPFArrayTable<int> t_ns1_a = bpf_ns1_a.get_array_table<int>("mysharedtable");
  ebpf::BPFArrayTable<int> t_ns1_b = bpf_ns1_b.get_array_table<int>("mysharedtable");
  ebpf::BPFArrayTable<int> t_ns2_a = bpf_ns2_a.get_array_table<int>("mysharedtable");
  ebpf::BPFArrayTable<int> t_ns2_b = bpf_ns2_b.get_array_table<int>("mysharedtable");

  // test that tables within the same ns are shared
  int v1, v2, v3;
  res = t_ns1_a.update_value(13, 42);
  REQUIRE(res.code() == 0);

  res = t_ns1_b.get_value(13, v1);
  REQUIRE(res.code() == 0);
  REQUIRE(v1 == 42);

  // test that tables are isolated within different ns
  res = t_ns2_a.update_value(13, 69);
  REQUIRE(res.code() == 0);

  res = t_ns2_b.get_value(13, v2);
  REQUIRE(res.code() == 0);
  REQUIRE(v2 == 69);

  res = t_ns1_b.get_value(13, v3);
  REQUIRE(res.code() == 0);
  REQUIRE(v3 == 42);  // value should still be 42
}
