#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

#include "sput.h"
#include "bcc_elf.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

static void test_procutils__which_so(void) {
  const char *libm = bcc_procutils_which_so("m");
  sput_fail_unless(libm, "find libm");
  sput_fail_unless(libm[0] == '/', "resolve libm absolute path");
  sput_fail_unless(strstr(libm, "libm.so"), "resolve libm so");
}

static void test_procutils__which(void) {
  char *ld = bcc_procutils_which("ld");
  sput_fail_unless(ld, "find `ld` binary");
  sput_fail_unless(ld[0] == '/', "find `ld` absolute path");
  free(ld);
}

static void _test_ksym(const char *sym, uint64_t addr, void *_) {
  if (!strcmp(sym, "startup_64")) {
    sput_fail_unless(addr == 0xffffffff81000000ull, "ksym `startup_64`");
  } else if (!strcmp(sym, "__per_cpu_start"))
    sput_fail_unless(addr == 0x0, "ksym `__per_cpu_start`");
}

static void test_procutils__each_ksym(void) {
  sput_fail_unless(geteuid() == 0, "ensure we are root");
  bcc_procutils_each_ksym(_test_ksym, NULL);
}

static void test_syms__resolve_symname(void) {
  struct bcc_symbol sym;

  sput_fail_unless(bcc_resolve_symname("c", "malloc", 0x0, &sym) == 0,
                   "bcc_resolve_symname(c, malloc)");

  sput_fail_unless(strstr(sym.module, "libc.so"), "resolve to module");
  sput_fail_unless(sym.module[0] == '/', "resolve to abspath");

  sput_fail_unless(sym.offset != 0, "resolve sym offset");
}

static void test_syms__resolver_pid(void) {
  struct bcc_symbol sym;
  void *resolver = bcc_symcache_new(getpid());

  sput_fail_unless(resolver, "create a new resolver for PID");

  sput_fail_unless(bcc_symcache_resolve(
                       resolver, (uint64_t)&test_syms__resolver_pid, &sym) == 0,
                   "resolve the current function address");

  char *this_exe = realpath("/proc/self/exe", NULL);
  sput_fail_unless(strcmp(this_exe, sym.module) == 0,
                   "resolve a function to our own binary");
  free(this_exe);

  sput_fail_unless(strcmp("test_syms__resolver_pid", sym.name) == 0,
                   "resolve a function to its actual name");

  void *libbcc = dlopen("libbcc.so", RTLD_LAZY | RTLD_NOLOAD);
  sput_fail_unless(libbcc, "dlopen(libbcc.so)");
  void *libbcc_fptr = dlsym(libbcc, "bcc_resolve_symname");
  sput_fail_unless(libbcc_fptr, "dlsym(bcc_resolve_symname)");

  sput_fail_unless(
      bcc_symcache_resolve(resolver, (uint64_t)libbcc_fptr, &sym) == 0,
      "resolve a function in libbcc in our current process");

  sput_fail_unless(strstr(sym.module, "libbcc.so"),
                   "resolve a function to the loaded libbcc module");

  sput_fail_unless(strcmp("bcc_resolve_symname", sym.name) == 0,
                   "resolve a function in libbcc to its actual name");

  void *libc_fptr = dlsym(NULL, "strtok");
  sput_fail_unless(libc_fptr, "dlsym(strtok)");

  sput_fail_unless(
      bcc_symcache_resolve(resolver, (uint64_t)libc_fptr, &sym) == 0,
      "resolve a function in libc in our current process");

  sput_fail_unless(
      sym.module && sym.module[0] == '/' && strstr(sym.module, "libc"),
      "resolve a function to linked libc module");

  sput_fail_unless(strcmp("strtok", sym.name) == 0,
                   "resolve a function in libc to its actual name");
}

int main(int argc, char *argv[]) {
  sput_start_testing();

  sput_enter_suite("procutils: which_so");
  sput_run_test(test_procutils__which_so);

  sput_enter_suite("procutils: which");
  sput_run_test(test_procutils__which);

  sput_enter_suite("procutils: each_ksym");
  sput_run_test(test_procutils__each_ksym);

  sput_enter_suite("syms: resolve_symname");
  sput_run_test(test_syms__resolve_symname);

  sput_enter_suite("syms: resolver_pid");
  sput_run_test(test_syms__resolver_pid);

  sput_finish_testing();
  return sput_get_return_value();
}
