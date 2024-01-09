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
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "bcc_syms.h"
#include "catch.hpp"
#include "common.h"
#include "vendor/tinyformat.hpp"

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

static void _test_ksym(const char *sym, const char *mod, uint64_t addr, void *_) {
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
  REQUIRE(string(sym.module).find(LIBBCC_NAME) != string::npos);
  REQUIRE(sym.module[0] == '/');
  REQUIRE(sym.offset != 0);
  bcc_procutils_free(sym.module);
}

namespace {

static std::string zipped_lib_path() {
  return CMAKE_CURRENT_BINARY_DIR "/archive.zip!/libdebuginfo_test_lib.so";
}

}  // namespace

TEST_CASE("resolve symbol name in external zipped library", "[c_api]") {
  struct bcc_symbol sym;
  REQUIRE(bcc_resolve_symname(zipped_lib_path().c_str(), "symbol", 0x0, 0,
                              nullptr, &sym) == 0);
  REQUIRE(sym.module == zipped_lib_path());
  REQUIRE(sym.offset != 0);
  bcc_procutils_free(sym.module);
}

namespace {

void system(const std::string &command) {
  if (::system(command.c_str())) {
    abort();
  }
}

class TmpDir {
 public:
  TmpDir() : path_("/tmp/bcc-test-XXXXXX") {
    if (::mkdtemp(&path_[0]) == nullptr) {
      abort();
    }
  }

  ~TmpDir() { system("rm -rf " + path_); }

  const std::string &path() const { return path_; }

 private:
  std::string path_;
};

void test_debuginfo_only_symbol(const std::string &lib) {
  struct bcc_symbol sym;
  REQUIRE(bcc_resolve_symname(lib.c_str(), "debuginfo_only_symbol", 0x0, 0,
                              nullptr, &sym) == 0);
  REQUIRE(sym.module[0] == '/');
  REQUIRE(sym.offset != 0);
  bcc_procutils_free(sym.module);
}

}  // namespace

TEST_CASE("resolve symbol name via symfs", "[c_api]") {
  TmpDir tmpdir;
  std::string lib_path = tmpdir.path() + "/lib.so";
  std::string symfs = tmpdir.path() + "/symfs";
  std::string symfs_lib_dir = symfs + "/" + tmpdir.path();
  std::string symfs_lib_path = symfs_lib_dir + "/lib.so";

  system("mkdir -p " + symfs);
  system("cp " CMAKE_CURRENT_BINARY_DIR "/libdebuginfo_test_lib.so " +
         lib_path);
  system("mkdir -p " + symfs_lib_dir);
  system("cp " CMAKE_CURRENT_BINARY_DIR "/debuginfo.so " + symfs_lib_path);

  ::setenv("BCC_SYMFS", symfs.c_str(), 1);
  test_debuginfo_only_symbol(lib_path);
  ::unsetenv("BCC_SYMFS");
}

TEST_CASE("resolve symbol name via buildid", "[c_api]") {
  char build_id[128] = {0};
  REQUIRE(bcc_elf_get_buildid(CMAKE_CURRENT_BINARY_DIR
                              "/libdebuginfo_test_lib.so",
                              build_id) == 0);

  TmpDir tmpdir;
  std::string debugso_dir =
      tmpdir.path() + "/.build-id/" + build_id[0] + build_id[1];
  std::string debugso = debugso_dir + "/" + (build_id + 2) + ".debug";
  system("mkdir -p " + debugso_dir);
  system("cp " CMAKE_CURRENT_BINARY_DIR "/debuginfo.so " + debugso);

  ::setenv("BCC_DEBUGINFO_ROOT", tmpdir.path().c_str(), 1);
  test_debuginfo_only_symbol(CMAKE_CURRENT_BINARY_DIR
                             "/libdebuginfo_test_lib.so");
  ::unsetenv("BCC_DEBUGINFO_ROOT");
}

TEST_CASE("resolve symbol name via gnu_debuglink", "[c_api]") {
  test_debuginfo_only_symbol(CMAKE_CURRENT_BINARY_DIR "/with_gnu_debuglink.so");
}

#ifdef HAVE_LIBLZMA
TEST_CASE("resolve symbol name via mini debug info", "[c_api]") {
  test_debuginfo_only_symbol(CMAKE_CURRENT_BINARY_DIR "/with_gnu_debugdata.so");
}
#endif

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

  strncpy(libpath, lm->l_name, sizeof(libpath) - 1);
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
  struct bcc_symbol lazy_sym;
  static struct bcc_symbol_option lazy_opt{
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = 1,
#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
    .use_symbol_type = BCC_SYM_ALL_TYPES | (1 << STT_PPC64_ELFV2_SYM_LEP),
#else
    .use_symbol_type = BCC_SYM_ALL_TYPES,
#endif
  };
  void *resolver = bcc_symcache_new(getpid(), nullptr);
  void *lazy_resolver = bcc_symcache_new(getpid(), &lazy_opt);

  REQUIRE(resolver);
  REQUIRE(lazy_resolver);

  SECTION("resolve in our own binary memory space") {
    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)&_a_test_function, &sym) ==
            0);

    char *this_exe = realpath("/proc/self/exe", NULL);
    REQUIRE(string(this_exe) == sym.module);
    free(this_exe);

    REQUIRE(string("_a_test_function") == sym.name);

    REQUIRE(bcc_symcache_resolve(lazy_resolver, (uint64_t)&_a_test_function, &lazy_sym) ==
            0);
    REQUIRE(string(lazy_sym.name) == sym.name);
    REQUIRE(string(lazy_sym.module) == sym.module);
  }

  SECTION("resolve in " LIBBCC_NAME) {
    void *libbcc = dlopen(LIBBCC_NAME, RTLD_LAZY | RTLD_NOLOAD);
    REQUIRE(libbcc);

    void *libbcc_fptr = dlsym(libbcc, "bcc_resolve_symname");
    REQUIRE(libbcc_fptr);

    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)libbcc_fptr, &sym) == 0);
    REQUIRE(string(sym.module).find(LIBBCC_NAME) != string::npos);
    REQUIRE(string("bcc_resolve_symname") == sym.name);

    REQUIRE(bcc_symcache_resolve(lazy_resolver, (uint64_t)libbcc_fptr, &lazy_sym) == 0);
    REQUIRE(string(lazy_sym.module) == sym.module);
    REQUIRE(string(lazy_sym.name) == sym.name);
  }

  SECTION("resolve in libc") {
    void *libc_fptr = dlsym(NULL, "strtok");
    REQUIRE(libc_fptr);

    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)libc_fptr, &sym) == 0);
    REQUIRE(sym.module);
    REQUIRE(sym.module[0] == '/');
    REQUIRE(string(sym.module).find("libc") != string::npos);

    REQUIRE(bcc_symcache_resolve(lazy_resolver, (uint64_t)libc_fptr, &lazy_sym) == 0);
    REQUIRE(string(lazy_sym.module) == sym.module);
    REQUIRE(string(lazy_sym.name) == sym.name);

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
    uint64_t lazy_addr = 0;

    child = spawn_child(0, true, true, mntns_func);
    REQUIRE(child > 0);

    void *resolver = bcc_symcache_new(child, nullptr);
    REQUIRE(resolver);

    REQUIRE(bcc_symcache_resolve_name(resolver, "/tmp/libz.so.1", "zlibVersion",
        &addr) == 0);
    REQUIRE(addr != 0);

    void *lazy_resolver = bcc_symcache_new(child, &lazy_opt);
    REQUIRE(lazy_resolver);
    REQUIRE(bcc_symcache_resolve_name(lazy_resolver, "/tmp/libz.so.1", "zlibVersion",
        &lazy_addr) == 0);
    REQUIRE(lazy_addr == addr);
    bcc_free_symcache(resolver, child);
    bcc_free_symcache(lazy_resolver, child);
  }
  bcc_free_symcache(resolver, getpid());
  bcc_free_symcache(lazy_resolver, getpid());
}

TEST_CASE("resolve symbol addresses for an exited process", "[c-api]") {
  struct bcc_symbol sym;
  struct bcc_symbol lazy_sym;
  static struct bcc_symbol_option lazy_opt {
    .use_debug_file = 1, .check_debug_file_crc = 1, .lazy_symbolize = 1,
#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
    .use_symbol_type = BCC_SYM_ALL_TYPES | (1 << STT_PPC64_ELFV2_SYM_LEP),
#else
    .use_symbol_type = BCC_SYM_ALL_TYPES,
#endif
  };

  SECTION("resolve in current namespace") {
    pid_t child = spawn_child(nullptr, false, false, [](void *) {
      sleep(5);
      return 0;
    });
    void *resolver = bcc_symcache_new(child, nullptr);
    void *lazy_resolver = bcc_symcache_new(child, &lazy_opt);

    REQUIRE(resolver);
    REQUIRE(lazy_resolver);

    kill(child, SIGTERM);

    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)&_a_test_function, &sym) ==
            0);

    char *this_exe = realpath("/proc/self/exe", NULL);
    REQUIRE(string(this_exe) == sym.module);
    free(this_exe);

    REQUIRE(string("_a_test_function") == sym.name);

    REQUIRE(bcc_symcache_resolve(lazy_resolver, (uint64_t)&_a_test_function,
                                 &lazy_sym) == 0);
    REQUIRE(string(lazy_sym.name) == sym.name);
    REQUIRE(string(lazy_sym.module) == sym.module);
  }

  SECTION("resolve in separate pid namespace") {
    pid_t child = spawn_child(nullptr, true, false, [](void *) {
      sleep(5);
      return 0;
    });
    void *resolver = bcc_symcache_new(child, nullptr);
    void *lazy_resolver = bcc_symcache_new(child, &lazy_opt);

    REQUIRE(resolver);
    REQUIRE(lazy_resolver);

    kill(child, SIGTERM);

    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)&_a_test_function, &sym) ==
            0);

    char *this_exe = realpath("/proc/self/exe", NULL);
    REQUIRE(string(this_exe) == sym.module);
    free(this_exe);

    REQUIRE(string("_a_test_function") == sym.name);

    REQUIRE(bcc_symcache_resolve(lazy_resolver, (uint64_t)&_a_test_function,
                                 &lazy_sym) == 0);
    REQUIRE(string(lazy_sym.name) == sym.name);
    REQUIRE(string(lazy_sym.module) == sym.module);
  }

  SECTION("resolve in separate pid and mount namespace") {
    pid_t child = spawn_child(nullptr, true, true, [](void *) {
      sleep(5);
      return 0;
    });
    void *resolver = bcc_symcache_new(child, nullptr);
    void *lazy_resolver = bcc_symcache_new(child, &lazy_opt);

    REQUIRE(resolver);
    REQUIRE(lazy_resolver);

    kill(child, SIGTERM);

    REQUIRE(bcc_symcache_resolve(resolver, (uint64_t)&_a_test_function, &sym) ==
            0);

    char *this_exe = realpath("/proc/self/exe", NULL);
    REQUIRE(string(this_exe) == sym.module);
    free(this_exe);

    REQUIRE(string("_a_test_function") == sym.name);

    REQUIRE(bcc_symcache_resolve(lazy_resolver, (uint64_t)&_a_test_function,
                                 &lazy_sym) == 0);
    REQUIRE(string(lazy_sym.name) == sym.name);
    REQUIRE(string(lazy_sym.module) == sym.module);
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
    bcc_free_symcache(resolver, child);

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
    bcc_free_symcache(resolver, child);
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
    bcc_free_symcache(resolver, child);
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
    bcc_free_symcache(resolver, child);
  }



  munmap(map_addr, map_sz);
}

// must match exactly the defitinion of mod_search in bcc_syms.cc
struct mod_search {
  const char *name;
  uint64_t inode;
  uint64_t dev_major;
  uint64_t dev_minor;
  uint64_t addr;
  uint8_t inode_match_only;

  uint64_t start;
  uint64_t file_offset;
};

TEST_CASE("searching for modules in /proc/[pid]/maps", "[c_api][!mayfail]") {
  std::string dummy_maps_path = CMAKE_CURRENT_BINARY_DIR + std::string("/dummy_proc_map.txt");
  FILE *dummy_maps = fopen(dummy_maps_path.c_str(), "r");
  REQUIRE(dummy_maps != NULL);

  SECTION("name match") {
    fseek(dummy_maps, 0, SEEK_SET);

    struct mod_search search;
    memset(&search, 0, sizeof(struct mod_search));
    search.name = "/some/other/path/tolibs/lib/libutil-2.26.so";
    search.addr = 0x1;
    int res =  _procfs_maps_each_module(dummy_maps, 42, _bcc_syms_find_module,
                                        &search);
    REQUIRE(res == 0);
    REQUIRE(search.start == 0x7f1515bad000);
  }

  SECTION("expected failure to match (name only search)") {
    fseek(dummy_maps, 0, SEEK_SET);

    struct mod_search search;
    memset(&search, 0, sizeof(struct mod_search));
    search.name = "/lib/that/isnt/in/maps/libdoesntexist.so";
    search.addr = 0x1;
    int res =  _procfs_maps_each_module(dummy_maps, 42, _bcc_syms_find_module,
                                        &search);
    REQUIRE(res == -1);
  }

  SECTION("inode+dev match, names different") {
    fseek(dummy_maps, 0, SEEK_SET);

    struct mod_search search;
    memset(&search, 0, sizeof(struct mod_search));
    search.name = "/proc/5/root/some/other/path/tolibs/lib/libz.so.1.2.8";
    search.inode = 72809538;
    search.dev_major = 0x00;
    search.dev_minor = 0x1b;
    search.addr = 0x2;
    int res =  _procfs_maps_each_module(dummy_maps, 42, _bcc_syms_find_module,
                                        &search);
    REQUIRE(res == 0);
    REQUIRE(search.start == 0x7f15164b5000);
  }

  SECTION("inode+dev don't match, names same") {
    fseek(dummy_maps, 0, SEEK_SET);

    struct mod_search search;
    memset(&search, 0, sizeof(struct mod_search));
    search.name = "/some/other/path/tolibs/lib/libutil-2.26.so";
    search.inode = 9999999;
    search.dev_major = 0x42;
    search.dev_minor = 0x1b;
    search.addr = 0x2;
    int res =  _procfs_maps_each_module(dummy_maps, 42, _bcc_syms_find_module,
                                        &search);
    REQUIRE(res == -1);
  }

  SECTION("inodes match, dev_major/minor don't, expected failure") {
    fseek(dummy_maps, 0, SEEK_SET);

    struct mod_search search;
    memset(&search, 0, sizeof(struct mod_search));
    search.name = "/some/other/path/tolibs/lib/libutil-2.26.so";
    search.inode = 72809526;
    search.dev_major = 0x11;
    search.dev_minor = 0x11;
    search.addr = 0x2;
    int res =  _procfs_maps_each_module(dummy_maps, 42, _bcc_syms_find_module,
                                        &search);
    REQUIRE(res == -1);
  }

  SECTION("inodes match, dev_major/minor don't, match inode only") {
    fseek(dummy_maps, 0, SEEK_SET);

    struct mod_search search;
    memset(&search, 0, sizeof(struct mod_search));
    search.name = "/some/other/path/tolibs/lib/libutil-2.26.so";
    search.inode = 72809526;
    search.dev_major = 0x11;
    search.dev_minor = 0x11;
    search.addr = 0x2;
    search.inode_match_only = 1;
    int res =  _procfs_maps_each_module(dummy_maps, 42, _bcc_syms_find_module,
                                        &search);
    REQUIRE(res == 0);
    REQUIRE(search.start == 0x7f1515bad000);
  }

  fclose(dummy_maps);

  SECTION("seach for lib in zip") {
    std::string line =
        "7f151476e000-7f1514779000 r-xp 00001000 00:1b "
        "72809479 " CMAKE_CURRENT_BINARY_DIR "/archive.zip\n";
    dummy_maps = fmemopen(nullptr, line.size(), "w+");
    REQUIRE(fwrite(line.c_str(), line.size(), 1, dummy_maps) == 1);
    fseek(dummy_maps, 0, SEEK_SET);

    struct mod_search search;
    memset(&search, 0, sizeof(struct mod_search));
    std::string zip_entry_path = zipped_lib_path();
    search.name = zip_entry_path.c_str();
    int res = _procfs_maps_each_module(dummy_maps, getpid(),
                                       _bcc_syms_find_module, &search);
    REQUIRE(res == 0);
    REQUIRE(search.start == 0x7f151476e000);
    REQUIRE(search.file_offset < 0x1000);

    fclose(dummy_maps);
  }
}

TEST_CASE("resolve global addr in libc in this process", "[c_api][!mayfail]") {
  int pid = getpid();
  char *sopath = bcc_procutils_which_so("c", pid);
  uint64_t local_addr = 0x15;
  uint64_t global_addr;

  struct mod_search search;
  memset(&search, 0, sizeof(struct mod_search));
  search.name = sopath;

  int res = bcc_procutils_each_module(pid, _bcc_syms_find_module,
                                      &search);
  REQUIRE(res == 0);
  REQUIRE(search.start != 0);

  res = bcc_resolve_global_addr(pid, sopath, local_addr, 0, &global_addr);
  REQUIRE(res == 0);
  REQUIRE(global_addr == (search.start + local_addr - search.file_offset));
  free(sopath);
}

/* Consider the following scenario: we have some process that maps in a shared library [1] with a
 * USDT probe [2]. The shared library's .text section doesn't have matching address and file off
 * [3]. Since the location address in [2] is an offset relative to the base address of whatever.so
 * in whatever process is mapping it, we need to convert the location address 0x77b8c to a global
 * address in the process' address space in order to attach to the USDT.
 *
 * The formula for this (__so_calc_global_addr) is
 *   global_addr = offset + (mod_start_addr - mod_file_offset)
 *                        - (elf_sec_start_addr - elf_sec_file_offset)
 *
 * Which for our concrete example is
 *   global_addr = 0x77b8c + (0x7f6cda31e000 - 0x72000) - (0x73c90 - 0x72c90)
 *   global_addr = 0x7f6cda322b8c
 *
 * [1 - output from `cat /proc/PID/maps`]
 * 7f6cda2ab000-7f6cda31e000 r--p 00000000 00:2d 5370022276                 /whatever.so
 * 7f6cda31e000-7f6cda434000 r-xp 00072000 00:2d 5370022276                 /whatever.so
 * 7f6cda434000-7f6cda43d000 r--p 00187000 00:2d 5370022276                 /whatever.so
 * 7f6cda43d000-7f6cda43f000 rw-p 0018f000 00:2d 5370022276                 /whatever.so
 *
 * [2 - output from `readelf -n /whatever.so`]
 * stapsdt              0x00000038 NT_STAPSDT (SystemTap probe descriptors)
 *   Provider: test
 *   Name: test_probe
 *   Location: 0x0000000000077b8c, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
 *   Arguments: -8@$5
 *
 * [3 - output from `readelf -W --sections /whatever.so`]
 *   [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
 *   [16] .text             PROGBITS        0000000000073c90 072c90 1132dc 00  AX  0   0 16
 */
TEST_CASE("conversion of module offset to/from global_addr", "[c_api]") {
  uint64_t global_addr, offset, calc_offset, mod_start_addr, mod_file_offset;
  uint64_t elf_sec_start_addr, elf_sec_file_offset;

  /* Initialize per example in comment above */
  offset = 0x77b8c;
  mod_start_addr = 0x7f6cda31e000;
  mod_file_offset = 0x00072000;
  elf_sec_start_addr = 0x73c90;
  elf_sec_file_offset = 0x72c90;
  global_addr = __so_calc_global_addr(mod_start_addr, mod_file_offset,
                                      elf_sec_start_addr, elf_sec_file_offset,
                                      offset);
  REQUIRE(global_addr == 0x7f6cda322b8c);

  /* Reverse operation (global_addr -> offset) should yield original offset */
  calc_offset = __so_calc_mod_offset(mod_start_addr, mod_file_offset,
                                     elf_sec_start_addr, elf_sec_file_offset,
                                     global_addr);
  REQUIRE(calc_offset == offset);
}

TEST_CASE("get online CPUs", "[c_api]") {
	std::vector<int> cpus = ebpf::get_online_cpus();
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	REQUIRE(cpus.size() == num_cpus);
}
