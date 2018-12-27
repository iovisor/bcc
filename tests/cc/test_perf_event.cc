/*
 * Copyright (c) 2017 Facebook, Inc.
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

#include <linux/perf_event.h>
#include <linux/version.h>
#include <unistd.h>
#include <string>

#include "BPF.h"
#include "catch.hpp"

TEST_CASE("test read perf event", "[bpf_perf_event]") {
// The basic bpf_perf_event_read is supported since Kernel 4.3. However in that
// version it only supported HARDWARE and RAW events. On the other hand, our
// tests running on Jenkins won't have availiable HARDWARE counters since they
// are running on VMs. The support of other types of events such as SOFTWARE are
// only added since Kernel 4.13, hence we can only run the test since that.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  const std::string BPF_PROGRAM = R"(
    BPF_PERF_ARRAY(cnt, NUM_CPUS);
    BPF_HASH(val, int, u64, 1);
    BPF_HASH(ret, int, int, 1);
    BPF_HASH(counter, int, struct bpf_perf_event_value, 1);

    int on_sys_getuid(void *ctx) {
      int zero = 0;

      u64 v = cnt.perf_read(CUR_CPU_IDENTIFIER);
      if (((s64)v < 0) && ((s64)v > -256))
        return 0;
      val.update(&zero, &v);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
      u32 cpu = bpf_get_smp_processor_id();
      struct bpf_perf_event_value c = {0};
      int r = cnt.perf_counter_value(cpu, &c, sizeof(c));
      ret.update(&zero, &r);
      counter.update(&zero, &c);
    #endif
      return 0;
    }
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(
      BPF_PROGRAM,
      {"-DNUM_CPUS=" + std::to_string(sysconf(_SC_NPROCESSORS_ONLN))}, {});
  REQUIRE(res.code() == 0);
  res =
      bpf.open_perf_event("cnt", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
  REQUIRE(res.code() == 0);
  std::string getuid_fnname = bpf.get_syscall_fnname("getuid");
  res = bpf.attach_kprobe(getuid_fnname, "on_sys_getuid");
  REQUIRE(res.code() == 0);
  REQUIRE(getuid() >= 0);
  res = bpf.detach_kprobe(getuid_fnname);
  REQUIRE(res.code() == 0);
  res = bpf.close_perf_event("cnt");
  REQUIRE(res.code() == 0);

  auto val = bpf.get_hash_table<int, uint64_t>("val");
  REQUIRE(val[0] >= 0);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
  auto counter_table =
      bpf.get_hash_table<int, struct bpf_perf_event_value>("counter");
  auto counter = counter_table[0];
  auto ret = bpf.get_hash_table<int, int>("ret");
  REQUIRE(ret[0] == 0);
  REQUIRE(counter.counter >= 0);
  REQUIRE(counter.enabled > 0);
  REQUIRE(counter.running >= 0);
  REQUIRE(counter.running <= counter.enabled);
#endif
}

TEST_CASE("test attach perf event", "[bpf_perf_event]") {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
  const std::string BPF_PROGRAM = R"(
    BPF_HASH(pid, int, u64, 1);
    BPF_HASH(ret, int, int, 1);
    BPF_HASH(counter, int, struct bpf_perf_event_value, 1);

    int on_event(void *ctx) {
      int zero = 0;
      
      u64 p = bpf_get_current_pid_tgid();
      pid.update(&zero, &p);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
      struct bpf_perf_event_value c = {0};
      int r = bpf_perf_prog_read_value(ctx, &c, sizeof(c));
      ret.update(&zero, &r);
      counter.update(&zero, &c);
    #endif
      return 0;
    }
  )";

  ebpf::BPF bpf;
  ebpf::StatusTuple res(0);
  res = bpf.init(BPF_PROGRAM);
  REQUIRE(res.code() == 0);
  res = bpf.attach_perf_event(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK,
                              "on_event", 0, 1000);
  REQUIRE(res.code() == 0);
  sleep(1);
  res = bpf.detach_perf_event(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
  REQUIRE(res.code() == 0);

  auto pid = bpf.get_hash_table<int, uint64_t>("pid");
  REQUIRE(pid[0] >= 0);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
  auto counter_table =
      bpf.get_hash_table<int, struct bpf_perf_event_value>("counter");
  auto counter = counter_table[0];
  auto ret = bpf.get_hash_table<int, int>("ret");
  REQUIRE(ret[0] == 0);
  REQUIRE(counter.counter >= 0);
  // the program slept one second between perf_event attachment and detachment
  // in the above, so the enabled counter should be 1000000000ns or
  // more. But in reality, most of counters (if not all) are 9xxxxxxxx,
  // and I also saw one 8xxxxxxxx. So let us a little bit conservative here.
  REQUIRE(counter.enabled >= 800000000);
  REQUIRE(counter.running >= 0);
  REQUIRE(counter.running <= counter.enabled);
#endif
}
