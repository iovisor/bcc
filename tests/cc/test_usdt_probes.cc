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
    USDT::Probe *probe = ctx.find_probe("sample_probe_1");
    REQUIRE(probe != nullptr);

    REQUIRE(probe->in_shared_object() == false);
    REQUIRE(probe->name() == "sample_probe_1");
    REQUIRE(probe->provider() == "libbcc_test");
    REQUIRE(probe->bin_path().find("/test_libbcc") != std::string::npos);

    REQUIRE(probe->num_locations() == 1);
    REQUIRE(probe->num_arguments() == 2);
    REQUIRE(probe->need_enable() == false);

    REQUIRE(a_probed_function() != 0);

    std::ostringstream case_stream;
    REQUIRE(probe->usdt_cases(case_stream));

    std::string cases = case_stream.str();
    REQUIRE(cases.find("int32_t arg1") != std::string::npos);
    REQUIRE(cases.find("uint64_t arg2") != std::string::npos);
  }
}
#endif  // HAVE_SDT_HEADER

static size_t countsubs(const std::string &str, const std::string &sub) {
  size_t count = 0;
  for (size_t offset = str.find(sub); offset != std::string::npos;
       offset = str.find(sub, offset + sub.length())) {
    ++count;
  }
  return count;
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

TEST_CASE("test listing all USDT probes in Ruby/MRI", "[usdt]") {
  size_t mri_probe_count = 0;

  SECTION("without a running Ruby process") {
    USDT::Context ctx("ruby");

    if (!ctx.loaded())
      return;

    REQUIRE(ctx.num_probes() > 10);
    mri_probe_count = ctx.num_probes();

    SECTION("GC static probe") {
      USDT::Probe *probe = ctx.find_probe("gc__mark__begin");
      REQUIRE(probe != nullptr);

      REQUIRE(probe->in_shared_object() == true);
      REQUIRE(probe->name() == "gc__mark__begin");
      REQUIRE(probe->provider() == "ruby");
      REQUIRE(probe->bin_path().find("/ruby") != std::string::npos);

      REQUIRE(probe->num_locations() == 1);
      REQUIRE(probe->num_arguments() == 0);
      REQUIRE(probe->need_enable() == true);
    }

    SECTION("object creation probe") {
      USDT::Probe *probe = ctx.find_probe("object__create");
      REQUIRE(probe != nullptr);

      REQUIRE(probe->in_shared_object() == true);
      REQUIRE(probe->name() == "object__create");
      REQUIRE(probe->provider() == "ruby");
      REQUIRE(probe->bin_path().find("/ruby") != std::string::npos);

      REQUIRE(probe->num_locations() == 1);
      REQUIRE(probe->num_arguments() == 3);
      REQUIRE(probe->need_enable() == true);

      std::ostringstream thunks_stream;
      REQUIRE(probe->usdt_thunks(thunks_stream, "ruby_usdt"));

      std::string thunks = thunks_stream.str();
      REQUIRE(std::count(thunks.begin(), thunks.end(), '\n') == 1);
      REQUIRE(thunks.find("ruby_usdt_thunk_0") != std::string::npos);

      std::ostringstream case_stream;
      REQUIRE(probe->usdt_cases(case_stream));

      std::string cases = case_stream.str();
      REQUIRE(countsubs(cases, "arg1") == 2);
      REQUIRE(countsubs(cases, "arg2") == 2);
      REQUIRE(countsubs(cases, "arg3") == 2);

      REQUIRE(countsubs(cases, "uint64_t") == 4);
      REQUIRE(countsubs(cases, "int32_t") == 2);
    }

    SECTION("array creation probe") {
      USDT::Probe *probe = ctx.find_probe("array__create");
      REQUIRE(probe != nullptr);
      REQUIRE(probe->name() == "array__create");

      REQUIRE(probe->num_locations() == 7);
      REQUIRE(probe->num_arguments() == 3);
      REQUIRE(probe->need_enable() == true);

      std::ostringstream thunks_stream;
      REQUIRE(probe->usdt_thunks(thunks_stream, "ruby_usdt"));

      std::string thunks = thunks_stream.str();
      REQUIRE(std::count(thunks.begin(), thunks.end(), '\n') == 7);
      REQUIRE(thunks.find("ruby_usdt_thunk_0") != std::string::npos);
      REQUIRE(thunks.find("ruby_usdt_thunk_6") != std::string::npos);
      REQUIRE(thunks.find("ruby_usdt_thunk_7") == std::string::npos);

      std::ostringstream case_stream;
      REQUIRE(probe->usdt_cases(case_stream));

      std::string cases = case_stream.str();
      REQUIRE(countsubs(cases, "arg1") == 8);
      REQUIRE(countsubs(cases, "arg2") == 8);
      REQUIRE(countsubs(cases, "arg3") == 8);

      REQUIRE(countsubs(cases, "__loc_id") == 7);
      REQUIRE(cases.find("int64_t arg1 =") != std::string::npos);
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
      USDT::Probe *probe = ctx.find_probe("gc__mark__begin");
      REQUIRE(probe != nullptr);

      REQUIRE(probe->in_shared_object() == true);
      REQUIRE(probe->name() == "gc__mark__begin");
      REQUIRE(probe->provider() == "ruby");
      REQUIRE(probe->bin_path().find("/ruby") != std::string::npos);

      REQUIRE(probe->num_locations() == 1);
      REQUIRE(probe->num_arguments() == 0);
      REQUIRE(probe->need_enable() == true);
    }
  }
}
