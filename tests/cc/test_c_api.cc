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
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "bcc_syms.h"
#include "common.h"
#include "vendor/tinyformat.hpp"

#include "catch.hpp"

using namespace std;

TEST_CASE("shared object resolution", "[c_api]") {
  char *libm = bcc_procutils_which_so("m", 0);
  REQUIRE(libm);
  REQUIRE(libm[0] == '/');
  REQUIRE(string(libm).find("libm.so") != string::npos);
  free(libm);
}

TEST_CASE("shared object resolution using loaded libraries", "[c_api]") {
  char *libelf = bcc_procutils_which_so("elf", getpid());
  REQUIRE(libelf);
  REQUIRE(libelf[0] == '/');
  REQUIRE(string(libelf).find("libelf") != string::npos);
  free(libelf);
}

TEST_CASE("binary resolution with `which`", "[c_api]") {
  char *ld = bcc_procutils_which("ld");
  REQUIRE(ld);
  REQUIRE(ld[0] == '/');
  free(ld);
}

static void _test_ksym(const char *sym, uint64_t addr, void *_) {
  if (!strcmp(sym, "startup_64"))
    REQUIRE(addr != 0x0ull);
}

TEST_CASE("list all kernel symbols", "[c_api]") {
  if (geteuid() != 0)
    return;
  bcc_procutils_each_ksym(_test_ksym, NULL);
}

TEST_CASE("resolve symbol name in external library", "[c_api]") {
  struct bcc_symbol sym;

  REQUIRE(bcc_resolve_symname("c", "malloc", 0x0, 0, &sym) == 0);
  REQUIRE(string(sym.module).find("libc.so") != string::npos);
  REQUIRE(sym.module[0] == '/');
  REQUIRE(sym.offset != 0);
  bcc_procutils_free(sym.module);
}

TEST_CASE("resolve symbol name in external library using loaded libraries", "[c_api]") {
  struct bcc_symbol sym;

  REQUIRE(bcc_resolve_symname("bcc", "bcc_procutils_which", 0x0, getpid(), &sym) == 0);
  REQUIRE(string(sym.module).find("libbcc.so") != string::npos);
  REQUIRE(sym.module[0] == '/');
  REQUIRE(sym.offset != 0);
  bcc_procutils_free(sym.module);
}

extern "C" int _a_test_function(const char *a_string) {
  int i;
  for (i = 0; a_string[i]; ++i)
    ;
  return i;
}

TEST_CASE("resolve symbol addresses for a given PID", "[c_api]") {
  struct bcc_symbol sym;
  void *resolver = bcc_symcache_new(getpid());

  REQUIRE(resolver);

  SECTION("resolve in our own binary memory space") {
    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)&_a_test_function, &sym) ==
            0);

    char *this_exe = realpath("/proc/self/exe", NULL);
    REQUIRE(string(this_exe) == sym.module);
    free(this_exe);

    REQUIRE(string("_a_test_function") == sym.name);
  }

  SECTION("resolve in libbcc.so") {
    void *libbcc = dlopen("libbcc.so", RTLD_LAZY | RTLD_NOLOAD);
    REQUIRE(libbcc);

    void *libbcc_fptr = dlsym(libbcc, "bcc_resolve_symname");
    REQUIRE(libbcc_fptr);

    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)libbcc_fptr, &sym) == 0);
    REQUIRE(string(sym.module).find("libbcc.so") != string::npos);
    REQUIRE(string("bcc_resolve_symname") == sym.name);
  }

  SECTION("resolve in libc") {
    void *libc_fptr = dlsym(NULL, "strtok");
    REQUIRE(libc_fptr);

    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)libc_fptr, &sym) == 0);
    REQUIRE(sym.module);
    REQUIRE(sym.module[0] == '/');
    REQUIRE(string(sym.module).find("libc") != string::npos);
    REQUIRE(string("strtok") == sym.name);
  }
}

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

static string perf_map_path(pid_t pid) {
  return tfm::format("/tmp/perf-%d.map", pid);
}

static int child_func(void *arg) {
  unsigned long long map_addr = (unsigned long long)arg;

  string path = perf_map_path(getpid());
  FILE *file = fopen(path.c_str(), "w");
  if (file == NULL) {
    return -1;
  }
  fprintf(file, "%llx 10 dummy_fn\n", map_addr);
  fprintf(file, "%llx 10 right_next_door_fn\n", map_addr + 0x10);
  fclose(file);

  sleep(5);

  unlink(path.c_str());
  return 0;
}

static pid_t spawn_child(void *map_addr, bool own_pidns) {
  int flags = 0;
  if (own_pidns)
    flags |= CLONE_NEWPID;

  pid_t child = clone(child_func, /* stack grows down */ child_stack + STACK_SIZE,
      flags, (void*)map_addr);
  if (child < 0)
    return -1;

  sleep(1); // let the child get set up
  return child;
}

TEST_CASE("resolve symbols using /tmp/perf-pid.map", "[c_api]") {
  const int map_sz = 4096;
  void *map_addr = mmap(NULL, map_sz, PROT_READ | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(map_addr != MAP_FAILED);

  struct bcc_symbol sym;
  pid_t child = -1;

  SECTION("same namespace") {
    child = spawn_child(map_addr, /* own_pidns */ false);
    REQUIRE(child > 0);

    void *resolver = bcc_symcache_new(child);
    REQUIRE(resolver);

    REQUIRE(bcc_symcache_resolve(resolver, (unsigned long long)map_addr,
        &sym) == 0);
    REQUIRE(sym.module);
    REQUIRE(string(sym.module) == perf_map_path(child));
    REQUIRE(string("dummy_fn") == sym.name);

    REQUIRE(bcc_symcache_resolve(resolver, (unsigned long long)map_addr + 0x10,
        &sym) == 0);
    REQUIRE(sym.module);
    REQUIRE(string(sym.module) == perf_map_path(child));
    REQUIRE(string("right_next_door_fn") == sym.name);
  }

  SECTION("separate namespace") {
    child = spawn_child(map_addr, /* own_pidns */ true);
    REQUIRE(child > 0);

    void *resolver = bcc_symcache_new(child);
    REQUIRE(resolver);

    REQUIRE(bcc_symcache_resolve(resolver, (unsigned long long)map_addr,
        &sym) == 0);
    REQUIRE(sym.module);
    // child is PID 1 in its namespace
    REQUIRE(string(sym.module) == perf_map_path(1));
    REQUIRE(string("dummy_fn") == sym.name);
  }

  munmap(map_addr, map_sz);
}


TEST_CASE("get online CPUs", "[c_api]") {
	std::vector<int> cpus = ebpf::get_online_cpus();
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	REQUIRE(cpus.size() == num_cpus);
}
