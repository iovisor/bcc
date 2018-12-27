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

TEST_CASE("test prog table", "[prog_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_TABLE("prog", int, int, myprog, 16);
  )";

  const std::string BPF_PROGRAM2 = R"(
    int hello(struct __sk_buff *skb) {
      return 1;
    }
  )";

  ebpf::StatusTuple res(0);

  ebpf::BPF bpf;
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFProgTable t = bpf.get_prog_table("myprog");

  ebpf::BPF bpf2;
  res = bpf2.init(BPF_PROGRAM2);
  REQUIRE(res.code() == 0);

  int fd;
  res = bpf2.load_func("hello", BPF_PROG_TYPE_SCHED_CLS, fd);
  REQUIRE(res.code() == 0);

  SECTION("update and remove") {
    // update element
    res = t.update_value(0, fd);
    REQUIRE(res.code() == 0);

    // remove element
    res = t.remove_value(0);
    REQUIRE(res.code() == 0);

    // update out of range element
    res = t.update_value(17, fd);
    REQUIRE(res.code() != 0);

    // remove out of range element
    res = t.remove_value(17);
    REQUIRE(res.code() != 0);
  }
}
