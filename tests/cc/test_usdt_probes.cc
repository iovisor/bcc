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
#include <linux/version.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "catch.hpp"
#include "usdt.h"
#include "api/BPF.h"

/* required to insert USDT probes on this very executable --
 * we're gonna be testing them live! */
#include "folly/tracing/StaticTracepoint.h"

static int a_probed_function() {
  int an_int = 23 + getpid();
  void *a_pointer = malloc(4);
  FOLLY_SDT(libbcc_test, sample_probe_1, an_int, a_pointer);
  free(a_pointer);
  return an_int;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
FOLLY_SDT_DEFINE_SEMAPHORE(libbcc_test, sample_probe_2)
static int a_probed_function_with_sem() {
  int an_int = 23 + getpid();
  void *a_pointer = malloc(4);
  FOLLY_SDT_WITH_SEMAPHORE(libbcc_test, sample_probe_2, an_int, a_pointer);
  free(a_pointer);
  return an_int;
}
#endif // linux version  >= 4.20

extern "C" int lib_probed_function();

int call_shared_lib_func() {
  return lib_probed_function();
}

TEST_CASE("test finding a probe in our own process", "[usdt]") {
  USDT::Context ctx(getpid());
  REQUIRE(ctx.num_probes() >= 1);

  SECTION("our test probe") {
    auto probe = ctx.get("sample_probe_1");
    REQUIRE(probe);

    if(probe->in_shared_object(probe->bin_path()))
        return;
    REQUIRE(probe->name() == "sample_probe_1");
    REQUIRE(probe->provider() == "libbcc_test");
    REQUIRE(probe->bin_path().find("/test_libbcc") != std::string::npos);

    REQUIRE(probe->num_locations() == 1);
    REQUIRE(probe->num_arguments() == 2);
    REQUIRE(probe->need_enable() == false);

    REQUIRE(a_probed_function() != 0);
  }
}

TEST_CASE("test probe's attributes with C++ API", "[usdt]") {
    const ebpf::USDT u("/proc/self/exe", "libbcc_test", "sample_probe_1", "on_event");

    REQUIRE(u.binary_path() == "/proc/self/exe");
    REQUIRE(u.pid() == -1);
    REQUIRE(u.provider() == "libbcc_test");
    REQUIRE(u.name() == "sample_probe_1");
    REQUIRE(u.probe_func() == "on_event");
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

TEST_CASE("test fine probes in our own binary with C++ API", "[usdt]") {
    ebpf::BPF bpf;
    ebpf::USDT u("/proc/self/exe", "libbcc_test", "sample_probe_1", "on_event");

    auto res = bpf.init("int on_event() { return 0; }", {}, {u});
    REQUIRE(res.ok());

    res = bpf.attach_usdt_all();
    REQUIRE(res.ok());

    res = bpf.detach_usdt_all();
    REQUIRE(res.ok());
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

TEST_CASE("test find a probe in our process' shared libs with c++ API", "[usdt]") {
  ebpf::BPF bpf;
  ebpf::USDT u(::getpid(), "libbcc_test", "sample_lib_probe_1", "on_event");

  auto res = bpf.init("int on_event() { return 0; }", {}, {u});
  REQUIRE(res.msg() == "");
  REQUIRE(res.code() == 0);
}

TEST_CASE("test usdt partial init w/ fail init_usdt", "[usdt]") {
  ebpf::BPF bpf;
  ebpf::USDT u(::getpid(), "libbcc_test", "sample_lib_probe_nonexistent", "on_event");
  ebpf::USDT p(::getpid(), "libbcc_test", "sample_lib_probe_1", "on_event");

  // We should be able to fail initialization and subsequently do bpf.init w/o USDT
  // successfully
  auto res = bpf.init_usdt(u);
  REQUIRE(res.msg() != "");
  REQUIRE(res.code() != 0);

  // Shouldn't be necessary to re-init bpf object either after failure to init w/
  // bad USDT
  res = bpf.init("int on_event() { return 0; }", {}, {u});
  REQUIRE(res.msg() != "");
  REQUIRE(res.code() != 0);

  res = bpf.init_usdt(p);
  REQUIRE(res.msg() == "");
  REQUIRE(res.code() == 0);

  res = bpf.init("int on_event() { return 0; }", {}, {});
  REQUIRE(res.msg() == "");
  REQUIRE(res.code() == 0);
}

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

// Unsharing pid namespace requires forking
// this uses pgrep to find the child process, by searching for a process
// that has the unshare as its parent
static int unshared_child_pid(const int ppid) {
  int child_pid;
  char cmd[512];
  const char *cmdfmt = "pgrep -P %d";

  sprintf(cmd, cmdfmt, ppid);
  if (cmd_scanf(cmd, "%d", &child_pid) != 0) {
    return -1;
  }
  return child_pid;
}

// FIXME This seems like a legitimate bug with probing ruby where the
// ruby symbols are in libruby.so?
TEST_CASE("test listing all USDT probes in Ruby/MRI", "[usdt][!mayfail]") {
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

// These tests are expected to fail if there is no Ruby with dtrace probes
TEST_CASE("test probing running Ruby process in namespaces",
          "[usdt][!mayfail]") {
  SECTION("in separate mount namespace") {
    static char _unshare[] = "unshare";
    const char *const argv[4] = {_unshare, "--mount", "ruby", NULL};

    ChildProcess unshare(argv[0], (char **const)argv);
    if (!unshare.spawned())
      return;
    int ruby_pid = unshare.pid();

    ebpf::BPF bpf;
    ebpf::USDT u(ruby_pid, "ruby", "gc__mark__begin", "on_event");
    u.set_probe_matching_kludge(1);  // Also required for overlayfs...

    auto res = bpf.init("int on_event() { return 0; }", {}, {u});
    REQUIRE(res.msg() == "");
    REQUIRE(res.code() == 0);

    res = bpf.attach_usdt(u, ruby_pid);
    REQUIRE(res.code() == 0);

    res = bpf.detach_usdt(u, ruby_pid);
    REQUIRE(res.code() == 0);
  }

  SECTION("in separate mount namespace and separate PID namespace") {
    static char _unshare[] = "unshare";
    const char *const argv[8] = {_unshare,  "--fork", "--kill-child",
                                 "--mount", "--pid",  "--mount-proc",
                                 "ruby",    NULL};

    ChildProcess unshare(argv[0], (char **const)argv);
    if (!unshare.spawned())
      return;
    int ruby_pid = unshared_child_pid(unshare.pid());

    ebpf::BPF bpf;
    ebpf::USDT u(ruby_pid, "ruby", "gc__mark__begin", "on_event");
    u.set_probe_matching_kludge(1);  // Also required for overlayfs...

    auto res = bpf.init("int on_event() { return 0; }", {}, {u});
    REQUIRE(res.msg() == "");
    REQUIRE(res.code() == 0);

    res = bpf.attach_usdt(u, ruby_pid);
    REQUIRE(res.code() == 0);

    res = bpf.detach_usdt(u, ruby_pid);
    REQUIRE(res.code() == 0);

    struct bcc_symbol sym;
    std::string pid_root= "/proc/" + std::to_string(ruby_pid) + "/root/";
    std::string module = pid_root + "usr/local/bin/ruby";
    REQUIRE(bcc_resolve_symname(module.c_str(), "rb_gc_mark", 0x0, ruby_pid, nullptr, &sym) == 0);
    REQUIRE(std::string(sym.module).find(pid_root, 1) == std::string::npos);
  }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
TEST_CASE("Test uprobe refcnt semaphore activation", "[usdt]") {
    ebpf::BPF bpf;

    REQUIRE(!FOLLY_SDT_IS_ENABLED(libbcc_test, sample_probe_2));

    ebpf::USDT u("/proc/self/exe", "libbcc_test", "sample_probe_2", "on_event");

    auto res = bpf.init("int on_event() { return 0; }", {}, {u});
    REQUIRE(res.code() == 0);

    res = bpf.attach_usdt(u);
    REQUIRE(res.code() == 0);

    REQUIRE(FOLLY_SDT_IS_ENABLED(libbcc_test, sample_probe_2));

    res = bpf.detach_usdt(u);
    REQUIRE(res.code() == 0);

    REQUIRE(a_probed_function_with_sem() != 0);
}
#endif // linux version  >= 4.20
