/*
 * Copyright (c) 2020 Politecnico di Torino
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
#include <iostream>
#include <linux/version.h>

//Queue/Stack types are available only from 4.20
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
TEST_CASE("queue table", "[queue_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_QUEUE(myqueue, int, 30);
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFQueueStackTable<int> t = bpf.get_queuestack_table<int>("myqueue");

  SECTION("standard methods") {
    int i, val;
    std::string value;

    // insert elements
    for (i=0; i<30; i++) {
      res = t.push_value(i);
      REQUIRE(res.code() == 0);
    }

    // checking head (peek)
    res = t.get_head(val);
    REQUIRE(res.code() == 0);
    REQUIRE(val == 0);

    // retrieve elements
    for (i=0; i<30; i++) {
      res = t.pop_value(val);
      REQUIRE(res.code() == 0);
      REQUIRE(val == i);
    }
    // get non existing element
    res = t.pop_value(val);
    REQUIRE(res.code() != 0);
  }
}

TEST_CASE("stack table", "[stack_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_STACK(mystack, int, 30);
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFQueueStackTable<int> t = bpf.get_queuestack_table<int>("mystack");

  SECTION("standard methods") {
    int i, val;
    std::string value;

    // insert elements
    for (i=0; i<30; i++) {
      res = t.push_value(i);
      REQUIRE(res.code() == 0);
    }

    // checking head (peek)
    res = t.get_head(val);
    REQUIRE(res.code() == 0);
    REQUIRE(val == 29);

    // retrieve elements
    for (i=0; i<30; i++) {
      res = t.pop_value(val);
      REQUIRE(res.code() == 0);
      REQUIRE( val == (30 - 1 - i));
    }
    // get non existing element
    res = t.pop_value(val);
    REQUIRE(res.code() != 0);
  }
}
#endif
