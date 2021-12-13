/*
 * Copyright (c) 2019 Facebook, Inc.
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)

TEST_CASE("test hash of maps", "[hash_of_maps]") {
  {
    const std::string BPF_PROGRAM = R"(
      BPF_ARRAY(cntl, int, 1);
      BPF_ARRAY(ex1, int, 1024);
      BPF_ARRAY(ex2, int, 1024);
      BPF_ARRAY(ex3, u64, 1024);
      BPF_HASH_OF_MAPS(maps_hash, int, "ex1", 10);

      int syscall__getuid(void *ctx) {
         int key = 0, data, *val, cntl_val;
         void *inner_map;

         val = cntl.lookup(&key);
         if (!val || *val == 0)
           return 0;

         // cntl_val == 1 : lookup and update
         cntl_val = *val;
         inner_map = maps_hash.lookup(&key);
         if (!inner_map)
           return 0;

         if (cntl_val == 1) {
           val = bpf_map_lookup_elem(inner_map, &key);
           if (val) {
             data = 1;
             bpf_map_update_elem(inner_map, &key, &data, 0);
           }
         }

         return 0;
      }
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok());

    auto t = bpf.get_map_in_map_table<int>("maps_hash");
    auto ex1_table = bpf.get_array_table<int>("ex1");
    auto ex2_table = bpf.get_array_table<int>("ex2");
    auto ex3_table = bpf.get_array_table<unsigned long long>("ex3");
    int ex1_fd = ex1_table.get_fd();
    int ex2_fd = ex2_table.get_fd();
    int ex3_fd = ex3_table.get_fd();

    int key = 0, value = 0;
    res = t.update_value(key, ex1_fd);
    REQUIRE(res.ok());

    // updating already-occupied slot will succeed.
    res = t.update_value(key, ex2_fd);
    REQUIRE(res.ok());
    res = t.update_value(key, ex1_fd);
    REQUIRE(res.ok());

    // an in-compatible map
    key = 1;
    res = t.update_value(key, ex3_fd);
    REQUIRE(res.code() == -1);

    // hash table, any valid key should work as long
    // as hash table is not full.
    key = 10;
    res = t.update_value(key, ex2_fd);
    REQUIRE(res.ok());
    res = t.remove_value(key);
    REQUIRE(res.ok());

    // test effectiveness of map-in-map
    key = 0;
    std::string getuid_fnname = bpf.get_syscall_fnname("getuid");
    res = bpf.attach_kprobe(getuid_fnname, "syscall__getuid");
    REQUIRE(res.ok());

    auto cntl_table = bpf.get_array_table<int>("cntl");
    cntl_table.update_value(0, 1);
    REQUIRE(getuid() >= 0);
    res = ex1_table.get_value(key, value);
    REQUIRE(res.ok());
    REQUIRE(value > 0);

    res = bpf.detach_kprobe(getuid_fnname);
    REQUIRE(res.ok());

    res = t.remove_value(key);
    REQUIRE(res.ok());
  }
}

TEST_CASE("test hash of maps using custom key", "[hash_of_maps_custom_key]") {
  {
    const std::string BPF_PROGRAM = R"(
        struct custom_key {
          int value_1;
          int value_2;
        };

        BPF_ARRAY(cntl, int, 1);
        BPF_TABLE("hash", int, int, ex1, 1024);
        BPF_TABLE("hash", int, int, ex2, 1024);
        BPF_HASH_OF_MAPS(maps_hash, struct custom_key, "ex1", 10);

        int syscall__getuid(void *ctx) {
          struct custom_key hash_key = {1, 0};
          int key = 0, data, *val, cntl_val;
          void *inner_map;

          val = cntl.lookup(&key);
          if (!val || *val == 0)
            return 0;

          hash_key.value_2 = *val;
          inner_map = maps_hash.lookup(&hash_key);
          if (!inner_map)
            return 0;

          val = bpf_map_lookup_elem(inner_map, &key);
          if (!val) {
            data = 1;
            bpf_map_update_elem(inner_map, &key, &data, 0);
          } else {
            data = 1 + *val;
            bpf_map_update_elem(inner_map, &key, &data, 0);
          }

          return 0;
        }
    )";

    struct custom_key {
      int value_1;
      int value_2;
    };

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok());

    auto t = bpf.get_map_in_map_table<struct custom_key>("maps_hash");
    auto ex1_table = bpf.get_hash_table<int, int>("ex1");
    auto ex2_table = bpf.get_hash_table<int, int>("ex2");
    auto cntl_table = bpf.get_array_table<int>("cntl");
    int ex1_fd = ex1_table.get_fd();
    int ex2_fd = ex2_table.get_fd();

    // test effectiveness of map-in-map
    std::string getuid_fnname = bpf.get_syscall_fnname("getuid");
    res = bpf.attach_kprobe(getuid_fnname, "syscall__getuid");
    REQUIRE(res.ok());

    struct custom_key hash_key = {1, 1};

    res = t.update_value(hash_key, ex1_fd);
    REQUIRE(res.ok());

    struct custom_key hash_key2 = {1, 2};
    res = t.update_value(hash_key2, ex2_fd);
    REQUIRE(res.ok());

    int key = 0, value = 0, value2 = 0;

    // Can't get value when value didn't set.
    res = ex1_table.get_value(key, value);
    REQUIRE(!res.ok());
    REQUIRE(value == 0);

    // Call syscall__getuid, then set value to ex1_table
    res = cntl_table.update_value(key, 1);
    REQUIRE(res.ok());
    REQUIRE(getuid() >= 0);

    // Now we can get value from ex1_table
    res = ex1_table.get_value(key, value);
    REQUIRE(res.ok());
    REQUIRE(value >= 1);

    // Can't get value when value didn't set.
    res = ex2_table.get_value(key, value2);
    REQUIRE(!res.ok());
    REQUIRE(value2 == 0);

    // Call syscall__getuid, then set value to ex2_table
    res = cntl_table.update_value(key, 2);
    REQUIRE(res.ok());
    REQUIRE(getuid() >= 0);

    // Now we can get value from ex2_table
    res = ex2_table.get_value(key, value2);
    REQUIRE(res.ok());
    REQUIRE(value > 0);

    res = bpf.detach_kprobe(getuid_fnname);
    REQUIRE(res.ok());

    res = t.remove_value(hash_key);
    REQUIRE(res.ok());
    res = t.remove_value(hash_key2);
    REQUIRE(res.ok());
  }
}

TEST_CASE("test array of maps", "[array_of_maps]") {
  {
    const std::string BPF_PROGRAM = R"(
      BPF_ARRAY(cntl, int, 1);
      BPF_TABLE("hash", int, int, ex1, 1024);
      BPF_TABLE("hash", int, int, ex2, 1024);
      BPF_TABLE("hash", u64, u64, ex3, 1024);
      BPF_ARRAY_OF_MAPS(maps_array, "ex1", 10);

      int syscall__getuid(void *ctx) {
         int key = 0, data, *val, cntl_val;
         void *inner_map;

         val = cntl.lookup(&key);
         if (!val || *val == 0)
           return 0;

         // cntl_val == 1 : lookup and update
         // cntl_val == 2 : delete
         cntl_val = *val;
         inner_map = maps_array.lookup(&key);
         if (!inner_map)
           return 0;

         if (cntl_val == 1) {
           val = bpf_map_lookup_elem(inner_map, &key);
           if (!val) {
             data = 1;
             bpf_map_update_elem(inner_map, &key, &data, 0);
           }
         } else if (cntl_val == 2) {
           bpf_map_delete_elem(inner_map, &key);
         }

         return 0;
      }
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok());

    auto t = bpf.get_map_in_map_table<int>("maps_array");
    auto ex1_table = bpf.get_hash_table<int, int>("ex1");
    auto ex2_table = bpf.get_hash_table<int, int>("ex2");
    auto ex3_table =
        bpf.get_hash_table<unsigned long long, unsigned long long>("ex3");
    int ex1_fd = ex1_table.get_fd();
    int ex2_fd = ex2_table.get_fd();
    int ex3_fd = ex3_table.get_fd();

    int key = 0, value = 0;
    res = t.update_value(key, ex1_fd);
    REQUIRE(res.ok());

    // updating already-occupied slot will succeed.
    res = t.update_value(key, ex2_fd);
    REQUIRE(res.ok());
    res = t.update_value(key, ex1_fd);
    REQUIRE(res.ok());

    // an in-compatible map
    key = 1;
    res = t.update_value(key, ex3_fd);
    REQUIRE(res.code() == -1);

    // array table, out of bound access
    key = 10;
    res = t.update_value(key, ex2_fd);
    REQUIRE(res.code() == -1);

    // test effectiveness of map-in-map
    key = 0;
    std::string getuid_fnname = bpf.get_syscall_fnname("getuid");
    res = bpf.attach_kprobe(getuid_fnname, "syscall__getuid");
    REQUIRE(res.ok());

    auto cntl_table = bpf.get_array_table<int>("cntl");
    cntl_table.update_value(0, 1);

    REQUIRE(getuid() >= 0);
    res = ex1_table.get_value(key, value);
    REQUIRE(res.ok());
    REQUIRE(value == 1);

    cntl_table.update_value(0, 2);
    REQUIRE(getuid() >= 0);
    res = ex1_table.get_value(key, value);
    REQUIRE(res.code() == -1);

    res = bpf.detach_kprobe(getuid_fnname);
    REQUIRE(res.ok());

    res = t.remove_value(key);
    REQUIRE(res.ok());
  }
}
#endif
