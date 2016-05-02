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
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

#include "catch.hpp"

using namespace std;

TEST_CASE("shared object resolution", "[c_api]") {
  const char *libm = bcc_procutils_which_so("m");
  REQUIRE(libm);
  REQUIRE(libm[0] == '/');
  REQUIRE(string(libm).find("libm.so") != string::npos);
}

TEST_CASE("binary resolution with `which`", "[c_api]") {
  char *ld = bcc_procutils_which("ld");
  REQUIRE(ld);
  REQUIRE(ld[0] == '/');
  free(ld);
}

static void _test_ksym(const char *sym, uint64_t addr, void *_) {
  if (!strcmp(sym, "startup_64")) {
    REQUIRE(addr == 0xffffffff81000000ull);
  } else if (!strcmp(sym, "system_reset_pSeries"))
    REQUIRE(addr == 0xc000000000000100ull);
}

TEST_CASE("list all kernel symbols", "[c_api]") {
  if (geteuid() != 0)
    return;
  bcc_procutils_each_ksym(_test_ksym, NULL);
}

TEST_CASE("resolve symbol name in external library", "[c_api]") {
  struct bcc_symbol sym;

  REQUIRE(bcc_resolve_symname("c", "malloc", 0x0, &sym) == 0);
  REQUIRE(string(sym.module).find("libc.so") != string::npos);
  REQUIRE(sym.module[0] == '/');
  REQUIRE(sym.offset != 0);
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
