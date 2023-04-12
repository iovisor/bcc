/*
 * Copyright (c) 2019 Kinvolk GmbH
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
#include <sys/mount.h>

#include "BPF.h"
#include "catch.hpp"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
TEST_CASE("test pinned table", "[pinned_table]") {
  bool mounted = false;
  if (system("mount | grep /sys/fs/bpf")) {
    REQUIRE(system("mkdir -p /sys/fs/bpf") == 0);
    REQUIRE(system("mount -o nosuid,nodev,noexec,mode=700 -t bpf bpf /sys/fs/bpf") == 0);
    mounted = true;
  }
  // prepare test by pinning table to bpffs
  {
    const std::string BPF_PROGRAM = R"(
      BPF_TABLE("hash", u64, u64, ids, 1024);
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok());

    REQUIRE(bpf_obj_pin(bpf.get_hash_table<int, int>("ids").get_fd(), "/sys/fs/bpf/test_pinned_table") == 0);
  }

  // test table access
  {
    const std::string BPF_PROGRAM = R"(
      BPF_TABLE_PINNED("hash", u64, u64, ids, 0, "/sys/fs/bpf/test_pinned_table", BPF_F_NO_PREALLOC);
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    unlink("/sys/fs/bpf/test_pinned_table"); // can delete table here already
    REQUIRE(res.ok());

    auto t = bpf.get_hash_table<int, int>("ids");
    int key, value;

    // write element
    key = 0x08;
    value = 0x43;
    res = t.update_value(key, value);
    REQUIRE(res.ok());
    REQUIRE(t[key] == value);
  }

  // test create if not exist
  {
    const std::string BPF_PROGRAM = R"(
      BPF_TABLE_PINNED("hash", u64, u64, ids, 1024, "/sys/fs/bpf/test_pinned_table");
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok());
    unlink("/sys/fs/bpf/test_pinned_table");
  }

  if (mounted) {
    REQUIRE(umount("/sys/fs/bpf") == 0);
  }
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
TEST_CASE("test pinned sk_storage table", "[pinned_sk_storage_table]") {
  bool mounted = false;
  if (system("mount | grep /sys/fs/bpf")) {
    REQUIRE(system("mkdir -p /sys/fs/bpf") == 0);
    REQUIRE(system("mount -o nosuid,nodev,noexec,mode=700 -t bpf bpf /sys/fs/bpf") == 0);
    mounted = true;
  }
  // prepare test by pinning table to bpffs
  {
    const std::string BPF_PROGRAM = R"(
      BPF_SK_STORAGE(sk_stg, __u64);
      int test(struct __sk_buff *skb) { return 0; }
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok());

    REQUIRE(bpf_obj_pin(bpf.get_sk_storage_table<unsigned long long>("sk_stg").get_fd(), "/sys/fs/bpf/test_pinned_table") == 0);
  }

  // exercise <pinned_map>.sk_storage_get().
  {
    const std::string BPF_PROGRAM = R"(
      BPF_TABLE_PINNED("sk_storage", __u32, __u64, sk_stg, 0, "/sys/fs/bpf/test_pinned_table");
      int test(struct __sk_buff *skb) {
        struct bpf_sock *sk;
        __u64 *val;

        sk = skb->sk;
        if (!sk)
          return 0;
        sk = bpf_sk_fullsock(sk);
        if (!sk)
          return 0;

        val = sk_stg.sk_storage_get(sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);
        if (!val)
          return 0;

        return 1;
      }
    )";

    ebpf::BPF bpf;
    ebpf::StatusTuple res(0);
    res = bpf.init(BPF_PROGRAM);
    REQUIRE(res.ok());
    int prog_fd;
    res = bpf.load_func("test", BPF_PROG_TYPE_CGROUP_SKB, prog_fd);
    REQUIRE(res.ok());
  }

  unlink("/sys/fs/bpf/test_pinned_table");
  if (mounted) {
    REQUIRE(umount("/sys/fs/bpf") == 0);
  }
}
#endif
