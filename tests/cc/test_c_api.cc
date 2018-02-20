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
#include <fcntl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "bcc_syms.h"
#include "common.h"
#include "vendor/tinyformat.hpp"

#include "catch.hpp"

using namespace std;

static pid_t spawn_child(void *, bool, bool, int (*)(void *));

TEST_CASE("language detection", "[c_api]") {
  const char *c = bcc_procutils_language(getpid());
  REQUIRE(c);
  REQUIRE(string(c).compare("c") == 0);
}

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

TEST_CASE("file-backed mapping identification") {
  CHECK(bcc_mapping_is_file_backed("/bin/ls") == 1);
  CHECK(bcc_mapping_is_file_backed("") == 0);
  CHECK(bcc_mapping_is_file_backed("//anon") == 0);
  CHECK(bcc_mapping_is_file_backed("/dev/zero") == 0);
  CHECK(bcc_mapping_is_file_backed("/anon_hugepage") == 0);
  CHECK(bcc_mapping_is_file_backed("/anon_hugepage (deleted)") == 0);
  CHECK(bcc_mapping_is_file_backed("[stack") == 0);
  CHECK(bcc_mapping_is_file_backed("/SYSV") == 0);
  CHECK(bcc_mapping_is_file_backed("[heap]") == 0);
}

TEST_CASE("resolve symbol name in external library", "[c_api]") {
  struct bcc_symbol sym;

  REQUIRE(bcc_resolve_symname("c", "malloc", 0x0, 0, nullptr, &sym) == 0);
  REQUIRE(string(sym.module).find("libc.so") != string::npos);
  REQUIRE(sym.module[0] == '/');
  REQUIRE(sym.offset != 0);
  bcc_procutils_free(sym.module);
}

TEST_CASE("resolve symbol name in external library using loaded libraries", "[c_api]") {
  struct bcc_symbol sym;

  REQUIRE(bcc_resolve_symname("bcc", "bcc_procutils_which", 0x0, getpid(), nullptr, &sym) == 0);
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

static int setup_tmp_mnts(void) {
  // Disconnect this mount namespace from its parent
  if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0) {
    fprintf(stderr, "unable to mark / PRIVATE: %s\n", strerror(errno));
    return -1;
  }
  // create a new tmpfs mounted on /tmp
  if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0) {
    fprintf(stderr, "unable to mount /tmp in mntns: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

static int mntns_func(void *arg) {
  int in_fd, out_fd;
  char buf[4096];
  char libpath[1024];
  ssize_t rb;
  void *dlhdl;
  struct link_map *lm;

  if (setup_tmp_mnts() < 0) {
    return -1;
  }

  // Find libz.so.1, if it's installed
  dlhdl = dlopen("libz.so.1", RTLD_LAZY);
  if (dlhdl == NULL) {
    fprintf(stderr, "Unable to dlopen libz.so.1: %s\n", dlerror());
    return -1;
  }

  if (dlinfo(dlhdl, RTLD_DI_LINKMAP, &lm) < 0) {
    fprintf(stderr, "Unable to find origin of libz.so.1: %s\n", dlerror());
    return -1;
  }

  strncpy(libpath, lm->l_name, 1024);
  dlclose(dlhdl);
  dlhdl = NULL;

  // Copy a shared library from shared mntns to private /tmp
  snprintf(buf, 4096, "%s", libpath);
  in_fd = open(buf, O_RDONLY);
  if (in_fd < 0) {
    fprintf(stderr, "Unable to open %s: %s\n", buf, strerror(errno));
    return -1;
  }

  out_fd = open("/tmp/libz.so.1", O_RDWR|O_CREAT|O_EXCL,
      S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
  if (out_fd < 0) {
    fprintf(stderr, "Unable to open /tmp/libz.so.1: %s\n", strerror(errno));
    return -1;
  }
  memset(buf, 0, sizeof (buf));
  while ((rb = read(in_fd, buf, sizeof (buf))) > 0) {
    if (write(out_fd, buf, rb) < 0) {
      fprintf(stderr, "Write error: %s\n", strerror(errno));
      return -1;
    }
  }
  close(in_fd);
  close(out_fd);

  dlhdl = dlopen("/tmp/libz.so.1", RTLD_NOW);
  if (dlhdl == NULL) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    return -1;
  }

  sleep(5);
  dlclose(dlhdl);

  return 0;
}

extern int cmd_scanf(const char *cmd, const char *fmt, ...);

TEST_CASE("resolve symbol addresses for a given PID", "[c_api]") {
  struct bcc_symbol sym;
  void *resolver = bcc_symcache_new(getpid(), nullptr);

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

    // In some cases, a symbol may have multiple aliases. Since
    // bcc_symcache_resolve() returns only the first alias of a
    // symbol, this may not always be "strtok" even if it points
    // to the same address.
    bool sym_match = (string("strtok") == sym.name);
    if (!sym_match) {
      uint64_t exp_addr, sym_addr;
      char cmd[256];
      const char *cmdfmt = "nm %s | grep \" %s$\" | cut -f 1 -d \" \"";

      // Find address of symbol by the expected name
      sprintf(cmd, cmdfmt, sym.module, "strtok");
      REQUIRE(cmd_scanf(cmd, "%lx", &exp_addr) == 0);

      // Find address of symbol by the name that was
      // returned by bcc_symcache_resolve()
      sprintf(cmd, cmdfmt, sym.module, sym.name);
      REQUIRE(cmd_scanf(cmd, "%lx", &sym_addr) == 0);

      // If both addresses match, they are definitely
      // aliases of the same symbol
      sym_match = (exp_addr == sym_addr);
    }

    REQUIRE(sym_match);
  }

  SECTION("resolve in separate mount namespace") {
    pid_t child;
    uint64_t addr = 0;

    child = spawn_child(0, true, true, mntns_func);
    REQUIRE(child > 0);

    void *resolver = bcc_symcache_new(child, nullptr);
    REQUIRE(resolver);

    REQUIRE(bcc_symcache_resolve_name(resolver, "/tmp/libz.so.1", "zlibVersion",
        &addr) == 0);
    REQUIRE(addr != 0);
  }
}

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

static string perf_map_path(pid_t pid) {
  return tfm::format("/tmp/perf-%d.map", pid);
}

static int make_perf_map_file(string &path, unsigned long long map_addr) {
  FILE *file = fopen(path.c_str(), "w");
  if (file == NULL) {
    return -1;
  }
  fprintf(file, "%llx 10 dummy_fn\n", map_addr);
  fprintf(file, "%llx 10 right_next_door_fn\n", map_addr + 0x10);
  fclose(file);

  return 0;
}

static int perf_map_func(void *arg) {
  string path = perf_map_path(getpid());
  if (make_perf_map_file(path, (unsigned long long)arg) < 0)
    return -1;

  sleep(5);

  unlink(path.c_str());
  return 0;
}

static int perf_map_func_mntns(void *arg) {
  string path = perf_map_path(getpid());

  if (setup_tmp_mnts() < 0) {
    return -1;
  }

  if (make_perf_map_file(path, (unsigned long long)arg) < 0)
    return -1;

  sleep(5);

  unlink(path.c_str());
  return 0;
}

static int perf_map_func_noop(void *arg) {
  if (setup_tmp_mnts() < 0) {
    return -1;
  }

  sleep(5);

  return 0;
}

static pid_t spawn_child(void *map_addr, bool own_pidns, bool own_mntns,
    int (*child_func)(void *)) {
  int flags = SIGCHLD;
  if (own_pidns)
    flags |= CLONE_NEWPID;
  if (own_mntns)
    flags |= CLONE_NEWNS;

  pid_t child = clone(child_func,
      /* stack grows down */ child_stack + STACK_SIZE, flags, (void*)map_addr);
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
    child = spawn_child(map_addr, /* own_pidns */ false, false, perf_map_func);
    REQUIRE(child > 0);

    void *resolver = bcc_symcache_new(child, nullptr);
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
    child = spawn_child(map_addr, /* own_pidns */ true, false, perf_map_func);
    REQUIRE(child > 0);

    void *resolver = bcc_symcache_new(child, nullptr);
    REQUIRE(resolver);

    REQUIRE(bcc_symcache_resolve(resolver, (unsigned long long)map_addr,
        &sym) == 0);
    REQUIRE(sym.module);
    // child is PID 1 in its namespace
    REQUIRE(string(sym.module) == perf_map_path(1));
    REQUIRE(string("dummy_fn") == sym.name);
    unlink("/tmp/perf-1.map");
  }

  SECTION("separate pid and mount namespace") {
    child = spawn_child(map_addr, /* own_pidns */ true, true,
        perf_map_func_mntns);
    REQUIRE(child > 0);

    void *resolver = bcc_symcache_new(child, nullptr);
    REQUIRE(resolver);

    REQUIRE(bcc_symcache_resolve(resolver, (unsigned long long)map_addr,
        &sym) == 0);
    REQUIRE(sym.module);
    // child is PID 1 in its namespace
    REQUIRE(string(sym.module) == perf_map_path(1));
    REQUIRE(string("dummy_fn") == sym.name);
  }

  SECTION("separate pid and mount namespace, perf-map in host") {
    child = spawn_child(map_addr, /* own_pidns */ true, true,
        perf_map_func_noop);
    REQUIRE(child > 0);

    string path = perf_map_path(child);
    REQUIRE(make_perf_map_file(path, (unsigned long long)map_addr) == 0);

    void *resolver = bcc_symcache_new(child, nullptr);
    REQUIRE(resolver);

    REQUIRE(bcc_symcache_resolve(resolver, (unsigned long long)map_addr,
        &sym) == 0);
    REQUIRE(sym.module);
    // child is PID 1 in its namespace
    REQUIRE(string(sym.module) == perf_map_path(child));
    REQUIRE(string("dummy_fn") == sym.name);

    unlink(path.c_str());
  }



  munmap(map_addr, map_sz);
}


TEST_CASE("get online CPUs", "[c_api]") {
	std::vector<int> cpus = ebpf::get_online_cpus();
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	REQUIRE(cpus.size() == num_cpus);
}
