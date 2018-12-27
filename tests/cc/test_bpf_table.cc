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

#include <linux/version.h>
#include <unistd.h>
#include <string>

#include "BPF.h"
#include "catch.hpp"

TEST_CASE("test bpf table", "[bpf_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_TABLE("hash", int, int, myhash, 128);
  )";

  ebpf::BPF *bpf(new ebpf::BPF);
  ebpf::StatusTuple res(0);
  std::vector<std::pair<std::string, std::string>> elements;
  res = bpf->init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFTable t = bpf->get_table("myhash");

  // update element
  std::string value;
  res = t.update_value("0x07", "0x42");
  REQUIRE(res.code() == 0);
  res = t.get_value("0x7", value);
  REQUIRE(res.code() == 0);
  REQUIRE(value == "0x42");

  // update another element
  res = t.update_value("0x11", "0x777");
  REQUIRE(res.code() == 0);
  res = t.get_value("0x11", value);
  REQUIRE(res.code() == 0);
  REQUIRE(value == "0x777");

  // remove value
  res = t.remove_value("0x11");
  REQUIRE(res.code() == 0);
  res = t.get_value("0x11", value);
  REQUIRE(res.code() != 0);

  res = t.update_value("0x15", "0x888");
  REQUIRE(res.code() == 0);
  res = t.get_table_offline(elements);
  REQUIRE(res.code() == 0);
  REQUIRE(elements.size() == 2);

  // check that elements match what is in the  table
  for (auto &it : elements) {
    if (it.first == "0x15") {
      REQUIRE(it.second == "0x888");
    } else if (it.first == "0x7") {
      REQUIRE(it.second == "0x42");
    } else {
      FAIL("Element " + it.first + " should not be on the table", it.first);
    }
  }

  res = t.clear_table_non_atomic();
  REQUIRE(res.code() == 0);
  res = t.get_table_offline(elements);
  REQUIRE(res.code() == 0);
  REQUIRE(elements.size() == 0);

  // delete bpf_module, call to key/leaf printf/scanf must fail
  delete bpf;

  res = t.update_value("0x07", "0x42");
  REQUIRE(res.code() != 0);

  res = t.get_value("0x07", value);
  REQUIRE(res.code() != 0);

  res = t.remove_value("0x07");
  REQUIRE(res.code() != 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
TEST_CASE("test bpf percpu tables", "[bpf_percpu_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_TABLE("percpu_hash", int, u64, myhash, 128);
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFTable t = bpf.get_table("myhash");
  size_t ncpus = ebpf::BPFTable::get_possible_cpu_count();

  std::vector<std::string> v1(ncpus);
  for (size_t i = 0; i < ncpus; i++) {
    v1.at(i) = std::to_string(42 * i);
  }

  // update element
  std::vector<std::string> value;
  res = t.update_value("0x07", v1);
  REQUIRE(res.code() == 0);
  res = t.get_value("0x07", value);
  REQUIRE(res.code() == 0);
  for (size_t i = 0; i < ncpus; i++) {
    REQUIRE(42 * i == std::stoul(value.at(i), nullptr, 16));
  }
}
#endif

TEST_CASE("test bpf hash table", "[bpf_hash_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_HASH(myhash, int, int, 128);
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  auto t = bpf.get_hash_table<int, int>("myhash");

  int key, value;

  // updaate element
  key = 0x08;
  value = 0x43;
  res = t.update_value(key, value);
  REQUIRE(res.code() == 0);
  REQUIRE(t[key] == value);

  // update another element
  key = 0x12;
  value = 0x778;
  res = t.update_value(key, value);
  REQUIRE(res.code() == 0);
  key = 0x31;
  value = 0x123;
  res = t.update_value(key, value);
  REQUIRE(res.code() == 0);
  key = 0x12;
  value = 0;
  res = t.get_value(key, value);
  REQUIRE(res.code() == 0);
  REQUIRE(value == 0x778);

  // remove value and dump table
  key = 0x12;
  res = t.remove_value(key);
  REQUIRE(res.code() == 0);
  auto values = t.get_table_offline();
  REQUIRE(values.size() == 2);

  // clear table
  res = t.clear_table_non_atomic();
  REQUIRE(res.code() == 0);
  values = t.get_table_offline();
  REQUIRE(values.size() == 0);
}

TEST_CASE("test bpf stack table", "[bpf_stack_table]") {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
  const std::string BPF_PROGRAM = R"(
    BPF_HASH(id, int, int, 1);
    BPF_STACK_TRACE(stack_traces, 8);

    int on_sys_getuid(void *ctx) {
      int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
      int zero = 0, *val;
      val = id.lookup_or_init(&zero, &stack_id);
      (*val) = stack_id;

      return 0;
    }
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);
  std::string getuid_fnname = bpf.get_syscall_fnname("getuid");
  res = bpf.attach_kprobe(getuid_fnname, "on_sys_getuid");
  REQUIRE(res.code() == 0);
  REQUIRE(getuid() >= 0);
  res = bpf.detach_kprobe(getuid_fnname);
  REQUIRE(res.code() == 0);

  auto id = bpf.get_hash_table<int, int>("id");
  auto stack_traces = bpf.get_stack_table("stack_traces");

  int stack_id = id[0];
  REQUIRE(stack_id >= 0);

  auto addrs = stack_traces.get_stack_addr(stack_id);
  auto symbols = stack_traces.get_stack_symbol(stack_id, -1);
  REQUIRE(addrs.size() > 0);
  REQUIRE(addrs.size() == symbols.size());
  bool found = false;
  for (const auto &symbol : symbols)
    if (symbol.find("sys_getuid") != std::string::npos) {
      found = true;
      break;
    }
  REQUIRE(found);

  stack_traces.clear_table_non_atomic();
  addrs = stack_traces.get_stack_addr(stack_id);
  REQUIRE(addrs.size() == 0);
#endif
}
