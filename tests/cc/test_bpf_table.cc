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

TEST_CASE("test bpf table", "[bpf_table]") {
  const std::string BPF_PROGRAM = R"(
    BPF_TABLE("hash", int, int, myhash, 128);
  )";

  ebpf::BPF *bpf(new ebpf::BPF);
  ebpf::StatusTuple res(0);
  res = bpf->init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);

  ebpf::BPFTable t = bpf->get_table("myhash");

  // update element
  std::string value;
  res = t.update_value("0x07", "0x42");
  REQUIRE(res.code() == 0);
  res = t.get_value("0x07", value);
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

  // delete bpf_module, call to key/leaf printf/scanf must fail
  delete bpf;

  res = t.update_value("0x07", "0x42");
  REQUIRE(res.code() != 0);

  res = t.get_value("0x07", value);
  REQUIRE(res.code() != 0);

  res = t.remove_value("0x07");
  REQUIRE(res.code() != 0);
}
