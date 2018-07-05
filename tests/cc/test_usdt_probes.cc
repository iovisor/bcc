/*
 * Copyright (c) 2016 GitHub, Inc.
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
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "catch.hpp"
#include "usdt.h"
#include "api/BPF.h"

#ifdef HAVE_SDT_HEADER
/* required to insert USDT probes on this very executable --
 * we're gonna be testing them live! */
#include <sys/sdt.h>

static int a_probed_function() {
  int an_int = 23 + getpid();
  void *a_pointer = malloc(4);
  DTRACE_PROBE2(libbcc_test, sample_probe_1, an_int, a_pointer);
  free(a_pointer);
  return an_int;
}

TEST_CASE("test finding a probe in our own process", "[usdt]") {
  USDT::Context ctx(getpid());
  REQUIRE(ctx.num_probes() >= 1);

  SECTION("our test probe") {
    auto probe = ctx.get("sample_probe_1");
    REQUIRE(probe);

    REQUIRE(probe->in_shared_object(probe->bin_path()) == false);
    REQUIRE(probe->name() == "sample_probe_1");
    REQUIRE(probe->provider() == "libbcc_test");
    REQUIRE(probe->bin_path().find("/test_libbcc") != std::string::npos);

    REQUIRE(probe->num_locations() == 1);
    REQUIRE(probe->num_arguments() == 2);
    REQUIRE(probe->need_enable() == false);

    REQUIRE(a_probed_function() != 0);
  }
}

TEST_CASE("test fine a probe in our own binary with C++ API", "[usdt]") {
    ebpf::BPF bpf;
    ebpf::USDT u("/proc/self/exe", "libbcc_test", "sample_probe_1", "on_event");

    auto res = bpf.init("int on_event() { return 0; }", {}, {u});
    REQUIRE(res.code() == 0);

    res = bpf.attach_usdt(u);
    REQUIRE(res.code() == 0);

    res = bpf.detach_usdt(u);
    REQUIRE(res.code() == 0);
}

TEST_CASE("test fine a probe in our Process with C++ API", "[usdt]") {
    ebpf::BPF bpf;
    ebpf::USDT u(::getpid(), "libbcc_test", "sample_probe_1", "on_event");

    auto res = bpf.init("int on_event() { return 0; }", {}, {u});
    REQUIRE(res.code() == 0);

    res = bpf.attach_usdt(u);
    REQUIRE(res.code() == 0);

    res = bpf.detach_usdt(u);
    REQUIRE(res.code() == 0);
}
#endif  // HAVE_SDT_HEADER

class ChildProcess {
  pid_t pid_;

public:
  ChildProcess(const char *name, char *const argv[]) {
    pid_ = fork();
    if (pid_ == 0) {
      execvp(name, argv);
      exit(0);
    }
    if (spawned()) {
      usleep(250000);
      if (kill(pid_, 0) < 0)
        pid_ = -1;
    }
  }

  ~ChildProcess() {
    if (spawned()) {
      int status;
      kill(pid_, SIGKILL);
      if (waitpid(pid_, &status, 0) != pid_)
        abort();
    }
  }

  bool spawned() const { return pid_ > 0; }
  pid_t pid() const { return pid_; }
};

extern int cmd_scanf(const char *cmd, const char *fmt, ...);

static int probe_num_locations(const char *bin_path, const char *func_name) {
  int num_locations;
  char cmd[512];
  const char *cmdfmt = "readelf -n %s | grep -c \"Name: %s$\"";

  sprintf(cmd, cmdfmt, bin_path, func_name);
  if (cmd_scanf(cmd, "%d", &num_locations) != 0) {
    return -1;
  }

  return num_locations;
}

static int probe_num_arguments(const char *bin_path, const char *func_name) {
  int num_arguments;
  char cmd[512];
  const char *cmdfmt = "readelf -n %s | grep -m 1 -A 2 \" %s$\" | " \
                       "tail -1 | cut -d \" \" -f 6- | wc -w";

  sprintf(cmd, cmdfmt, bin_path, func_name);
  if (cmd_scanf(cmd, "%d", &num_arguments) != 0) {
    return -1;
  }

  return num_arguments;
}

TEST_CASE("test listing all USDT probes in Ruby/MRI", "[usdt]") {
  size_t mri_probe_count = 0;

  SECTION("without a running Ruby process") {
    USDT::Context ctx("ruby");

    if (!ctx.loaded())
      return;

    REQUIRE(ctx.num_probes() > 10);
    mri_probe_count = ctx.num_probes();

    SECTION("GC static probe") {
      auto name = "gc__mark__begin";
      auto probe = ctx.get(name);
      REQUIRE(probe);

      REQUIRE(probe->in_shared_object(probe->bin_path()) == true);
      REQUIRE(probe->name() == name);
      REQUIRE(probe->provider() == "ruby");

      auto bin_path = probe->bin_path();
      bool bin_path_match =
            (bin_path.find("/ruby") != std::string::npos) ||
            (bin_path.find("/libruby") != std::string::npos);
      REQUIRE(bin_path_match);

      int exp_locations, exp_arguments;
      exp_locations = probe_num_locations(bin_path.c_str(), name);
      exp_arguments = probe_num_arguments(bin_path.c_str(), name);
      REQUIRE(probe->num_locations() == exp_locations);
      REQUIRE(probe->num_arguments() == exp_arguments);
      REQUIRE(probe->need_enable() == true);
    }

    SECTION("object creation probe") {
      auto name = "object__create";
      auto probe = ctx.get(name);
      REQUIRE(probe);

      REQUIRE(probe->in_shared_object(probe->bin_path()) == true);
      REQUIRE(probe->name() == name);
      REQUIRE(probe->provider() == "ruby");

      auto bin_path = probe->bin_path();
      bool bin_path_match =
            (bin_path.find("/ruby") != std::string::npos) ||
            (bin_path.find("/libruby") != std::string::npos);
      REQUIRE(bin_path_match);

      int exp_locations, exp_arguments;
      exp_locations = probe_num_locations(bin_path.c_str(), name);
      exp_arguments = probe_num_arguments(bin_path.c_str(), name);
      REQUIRE(probe->num_locations() == exp_locations);
      REQUIRE(probe->num_arguments() == exp_arguments);
      REQUIRE(probe->need_enable() == true);
    }

    SECTION("array creation probe") {
      auto name = "array__create";
      auto probe = ctx.get(name);
      REQUIRE(probe);
      REQUIRE(probe->name() == name);

      auto bin_path = probe->bin_path().c_str();
      int exp_locations, exp_arguments;
      exp_locations = probe_num_locations(bin_path, name);
      exp_arguments = probe_num_arguments(bin_path, name);
      REQUIRE(probe->num_locations() == exp_locations);
      REQUIRE(probe->num_arguments() == exp_arguments);
      REQUIRE(probe->need_enable() == true);
    }
  }

  SECTION("with a running Ruby process") {
    static char _ruby[] = "ruby";
    char *const argv[2] = {_ruby, NULL};

    ChildProcess ruby(argv[0], argv);
    if (!ruby.spawned())
      return;

    USDT::Context ctx(ruby.pid());
    REQUIRE(ctx.num_probes() >= mri_probe_count);

    SECTION("get probe in running process") {
      auto name = "gc__mark__begin";
      auto probe = ctx.get(name);
      REQUIRE(probe);

      REQUIRE(probe->in_shared_object(probe->bin_path()) == true);
      REQUIRE(probe->name() == name);
      REQUIRE(probe->provider() == "ruby");

      auto bin_path = probe->bin_path();
      bool bin_path_match =
            (bin_path.find("/ruby") != std::string::npos) ||
            (bin_path.find("/libruby") != std::string::npos);
      REQUIRE(bin_path_match);

      int exp_locations, exp_arguments;
      exp_locations = probe_num_locations(bin_path.c_str(), name);
      exp_arguments = probe_num_arguments(bin_path.c_str(), name);
      REQUIRE(probe->num_locations() == exp_locations);
      REQUIRE(probe->num_arguments() == exp_arguments);
      REQUIRE(probe->need_enable() == true);
    }
  }
}
