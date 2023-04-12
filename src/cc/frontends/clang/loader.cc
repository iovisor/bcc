/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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

#include <map>
#include <string>
#include <algorithm>
#include <fcntl.h>
#include <ftw.h>
#include <map>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <iostream>
#include <linux/bpf.h>

#include <clang/Basic/FileManager.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/CodeGen/BackendUtil.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>
#include <clang/Driver/Job.h>
#include <clang/Driver/Tool.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/CompilerInvocation.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/FrontendDiagnostic.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <clang/FrontendTool/Utils.h>
#include <clang/Lex/PreprocessorOptions.h>

#include <llvm/IR/Module.h>

#include "bcc_exception.h"
#include "bpf_module.h"
#include "exported_files.h"
#include "kbuild_helper.h"
#include "b_frontend_action.h"
#include "tp_frontend_action.h"
#include "loader.h"
#include "arch_helper.h"

using std::map;
using std::string;
using std::unique_ptr;
using std::vector;

namespace ebpf {

optional<FuncInfo &> ProgFuncInfo::get_func(std::string name) {
  auto it = funcs_.find(name);
  if (it != funcs_.end())
    return it->second;
  return nullopt;
}

optional<FuncInfo &> ProgFuncInfo::get_func(size_t id) {
  auto it = func_idx_.find(id);
  if (it != func_idx_.end())
    return get_func(it->second);
  return nullopt;
}

optional<std::string &> ProgFuncInfo::func_name(size_t id) {
  auto it = func_idx_.find(id);
  if (it != func_idx_.end())
    return it->second;
  return nullopt;
}

void ProgFuncInfo::for_each_func(
    std::function<void(std::string, FuncInfo &)> cb) {
  for (auto it = funcs_.begin(); it != funcs_.end(); ++it) {
    cb(it->first, it->second);
  }
}

optional<FuncInfo &> ProgFuncInfo::add_func(std::string name) {
  auto fn = get_func(name);
  if (fn)
    return nullopt;
  size_t current = funcs_.size();
  funcs_.emplace(name, 0);
  func_idx_.emplace(current, name);
  return get_func(name);
}

ClangLoader::ClangLoader(llvm::LLVMContext *ctx, unsigned flags)
    : ctx_(ctx), flags_(flags)
{
  for (auto f : ExportedFiles::headers())
    remapped_headers_[f.first] = llvm::MemoryBuffer::getMemBuffer(f.second);
  for (auto f : ExportedFiles::footers())
    remapped_footers_[f.first] = llvm::MemoryBuffer::getMemBuffer(f.second);
}

ClangLoader::~ClangLoader() {}

void ClangLoader::add_remapped_includes(clang::CompilerInvocation& invocation)
{
  // This option instructs clang whether or not to free the file buffers that we
  // give to it. Since the embedded header files should be copied fewer times
  // and reused if possible, set this flag to true.
  invocation.getPreprocessorOpts().RetainRemappedFileBuffers = true;
  for (const auto &f : remapped_headers_)
    invocation.getPreprocessorOpts().addRemappedFile(f.first, &*f.second);
  for (const auto &f : remapped_footers_)
    invocation.getPreprocessorOpts().addRemappedFile(f.first, &*f.second);
}

void ClangLoader::add_main_input(clang::CompilerInvocation& invocation,
                                 const std::string& main_path,
                                 llvm::MemoryBuffer *main_buf)
{
  invocation.getPreprocessorOpts().addRemappedFile(main_path, main_buf);
  invocation.getFrontendOpts().Inputs.clear();
  invocation.getFrontendOpts().Inputs.push_back(
      clang::FrontendInputFile(
        main_path,
        clang::FrontendOptions::getInputKindForExtension("c"))
  );
}

namespace
{

bool is_dir(const string& path)
{
  struct stat buf;

  if (::stat (path.c_str (), &buf) < 0)
    return false;

  return S_ISDIR(buf.st_mode);
}

bool is_file(const string& path)
{
  struct stat buf;

  if (::stat (path.c_str (), &buf) < 0)
    return false;

  return S_ISREG(buf.st_mode);
}

std::pair<bool, string> get_kernel_path_info(const string kdir)
{
  if (is_dir(kdir + "/build") && is_dir(kdir + "/source"))
    return std::make_pair (true, "source");

  const char* suffix_from_env = ::getenv("BCC_KERNEL_MODULES_SUFFIX");
  if (suffix_from_env)
    return std::make_pair(false, string(suffix_from_env));

  return std::make_pair(false, "build");
}

static int CreateFromArgs(clang::CompilerInvocation &invocation,
                          const llvm::opt::ArgStringList &ccargs,
                          clang::DiagnosticsEngine &diags)
{
#if LLVM_MAJOR_VERSION >= 10
  return clang::CompilerInvocation::CreateFromArgs(invocation, ccargs, diags);
#else
  return clang::CompilerInvocation::CreateFromArgs(
              invocation, const_cast<const char **>(ccargs.data()),
              const_cast<const char **>(ccargs.data()) + ccargs.size(), diags);
#endif
}

}

int ClangLoader::parse(
    unique_ptr<llvm::Module> *mod, TableStorage &ts, const string &file,
    bool in_memory, const char *cflags[], int ncflags, const std::string &id,
    ProgFuncInfo &prog_func_info, std::string &mod_src,
    const std::string &maps_ns, fake_fd_map_def &fake_fd_map,
    std::map<std::string, std::vector<std::string>> &perf_events) {
  string main_path = "/virtual/main.c";
  unique_ptr<llvm::MemoryBuffer> main_buf;
  struct utsname un;
  uname(&un);
  string kdir, kpath;
  const char *kpath_env = ::getenv("BCC_KERNEL_SOURCE");
  const char *version_override = ::getenv("BCC_LINUX_VERSION_CODE");
  bool has_kpath_source = false;
  string vmacro;
  std::string tmpdir;

  if (kpath_env) {
    kpath = string(kpath_env);
  } else {
    kdir = string(KERNEL_MODULES_DIR) + "/" + un.release;
    auto kernel_path_info = get_kernel_path_info(kdir);
    has_kpath_source = kernel_path_info.first;
    kpath = kdir + "/" + kernel_path_info.second;
  }

  // If all attempts to obtain kheaders fail, check for kheaders.tar.xz in sysfs
  // Checking just for kpath existence is unsufficient, since it can refer to
  // leftover build directory without headers present anymore.
  // See https://github.com/iovisor/bcc/pull/3588 for more details.
  if (!is_file(kpath + "/include/linux/kconfig.h")) {
    int ret = get_proc_kheaders(tmpdir);
    if (!ret) {
      kpath = tmpdir;
    } else {
      std::cout << "Unable to find kernel headers. ";
      std::cout << "Try rebuilding kernel with CONFIG_IKHEADERS=m (module) ";
      std::cout <<  "or installing the kernel development package for your running kernel version.\n";
    }
  }

  if (flags_ & DEBUG_PREPROCESSOR)
    std::cout << "Running from kernel directory at: " << kpath.c_str() << "\n";

  // clang needs to run inside the kernel dir
  DirStack dstack(kpath);
  if (!dstack.ok())
    return -1;

  string abs_file;
  if (in_memory) {
    abs_file = main_path;
    main_buf = llvm::MemoryBuffer::getMemBuffer(file);
  } else {
    if (file.substr(0, 1) == "/")
      abs_file = file;
    else
      abs_file = string(dstack.cwd()) + "/" + file;
  }

  // -fno-color-diagnostics: this is a workaround for a bug in llvm terminalHasColors() as of
  // 22 Jul 2016. Also see bcc #615.
  // Enable -O2 for clang. In clang 5.0, -O0 may result in function marking as
  // noinline and optnone (if not always inlining).
  // Note that first argument is ignored in clang compilation invocation.
  // "-D __BPF_TRACING__" below is added to suppress a warning in 4.17+.
  // It can be removed once clang supports asm-goto or the kernel removes
  // the warning.
  vector<const char *> flags_cstr({"-O0", "-O2", "-emit-llvm", "-I", dstack.cwd(),
                                   "-D", "__BPF_TRACING__",
                                   "-Wno-deprecated-declarations",
                                   "-Wno-gnu-variable-sized-type-not-at-end",
                                   "-Wno-pragma-once-outside-header",
                                   "-Wno-address-of-packed-member",
                                   "-Wno-unknown-warning-option",
                                   "-fno-color-diagnostics",
                                   "-fno-unwind-tables",
                                   "-fno-asynchronous-unwind-tables",
                                   "-x", "c", "-c", abs_file.c_str()});

  const char *arch = getenv("ARCH");
  if (!arch)
    arch = un.machine;

  if (!strncmp(arch, "mips", 4)) {
    flags_cstr.push_back("-D__MIPSEL__");
    flags_cstr.push_back("-D_MIPS_SZLONG=64");
  }

  KBuildHelper kbuild_helper(kpath_env ? kpath : kdir, has_kpath_source);

  vector<string> kflags;
  if (kbuild_helper.get_flags(un.machine, &kflags))
    return -1;
#if LLVM_MAJOR_VERSION >= 9
  flags_cstr.push_back("-g");
  flags_cstr.push_back("-gdwarf-4");
#else
  if (flags_ & DEBUG_SOURCE)
    flags_cstr.push_back("-g");
#endif
  for (auto it = kflags.begin(); it != kflags.end(); ++it)
    flags_cstr.push_back(it->c_str());

  vector<const char *> flags_cstr_rem;

  if (version_override) {
    vmacro = "-DLINUX_VERSION_CODE_OVERRIDE=" + string(version_override);

    std::cout << "WARNING: Linux version for eBPF program is being overridden with: " << version_override << "\n";
    std::cout << "WARNING: Due to this, the results of the program may be unpredictable\n";
    flags_cstr_rem.push_back(vmacro.c_str());
  }

  flags_cstr_rem.push_back("-include");
  flags_cstr_rem.push_back("/virtual/include/bcc/helpers.h");
  flags_cstr_rem.push_back("-isystem");
  flags_cstr_rem.push_back("/virtual/include");
  if (cflags) {
    for (auto i = 0; i < ncflags; ++i)
      flags_cstr_rem.push_back(cflags[i]);
  }
#ifdef CUR_CPU_IDENTIFIER
  string cur_cpu_flag = string("-DCUR_CPU_IDENTIFIER=") + CUR_CPU_IDENTIFIER;
  flags_cstr_rem.push_back(cur_cpu_flag.c_str());
#endif

  if (do_compile(mod, ts, in_memory, flags_cstr, flags_cstr_rem, main_path,
                 main_buf, id, prog_func_info, mod_src, true, maps_ns,
                 fake_fd_map, perf_events)) {
#if BCC_BACKUP_COMPILE != 1
    return -1;
#else
    // try one more time to compile with system bpf.h
    llvm::errs() << "WARNING: compilation failure, trying with system bpf.h\n";

    ts.DeletePrefix(Path({id}));
    prog_func_info.clear();
    mod_src.clear();
    fake_fd_map.clear();
    if (do_compile(mod, ts, in_memory, flags_cstr, flags_cstr_rem, main_path,
                   main_buf, id, prog_func_info, mod_src, false, maps_ns,
                   fake_fd_map, perf_events))
      return -1;
#endif
  }

  return 0;
}

void *get_clang_target_cb(bcc_arch_t arch, bool for_syscall)
{
  const char *ret;

  switch(arch) {
    case BCC_ARCH_PPC_LE:
      ret = "powerpc64le-unknown-linux-gnu";
      break;
    case BCC_ARCH_PPC:
      ret = "powerpc64-unknown-linux-gnu";
      break;
    case BCC_ARCH_S390X:
      ret = "s390x-ibm-linux-gnu";
      break;
    case BCC_ARCH_ARM64:
      ret = "aarch64-unknown-linux-gnu";
      break;
    case BCC_ARCH_MIPS:
      ret = "mips64el-unknown-linux-gnuabi64";
      break;
    case BCC_ARCH_RISCV64:
      ret = "riscv64-unknown-linux-gnu";
      break;
    case BCC_ARCH_LOONGARCH:
      ret = "loongarch64-unknown-linux-gnu";
      break;
    default:
      ret = "x86_64-unknown-linux-gnu";
  }

  return (void *)ret;
}

string get_clang_target(void) {
  const char *ret;

  ret = (const char *)run_arch_callback(get_clang_target_cb);
  return string(ret);
}

int ClangLoader::do_compile(
    unique_ptr<llvm::Module> *mod, TableStorage &ts, bool in_memory,
    const vector<const char *> &flags_cstr_in,
    const vector<const char *> &flags_cstr_rem, const std::string &main_path,
    const unique_ptr<llvm::MemoryBuffer> &main_buf, const std::string &id,
    ProgFuncInfo &prog_func_info, std::string &mod_src, bool use_internal_bpfh,
    const std::string &maps_ns, fake_fd_map_def &fake_fd_map,
    std::map<std::string, std::vector<std::string>> &perf_events) {
  using namespace clang;

  vector<const char *> flags_cstr = flags_cstr_in;
  if (use_internal_bpfh) {
    flags_cstr.push_back("-include");
    flags_cstr.push_back("/virtual/include/bcc/bpf.h");
  }
  flags_cstr.push_back("-include");
  flags_cstr.push_back("/virtual/include/bcc/bpf_workaround.h");
  flags_cstr.insert(flags_cstr.end(), flags_cstr_rem.begin(),
                    flags_cstr_rem.end());

  // set up the error reporting class
  IntrusiveRefCntPtr<DiagnosticOptions> diag_opts(new DiagnosticOptions());
  auto diag_client = new TextDiagnosticPrinter(llvm::errs(), &*diag_opts);

  IntrusiveRefCntPtr<DiagnosticIDs> DiagID(new DiagnosticIDs());
  DiagnosticsEngine diags(DiagID, &*diag_opts, diag_client);

  // set up the command line argument wrapper

  string target_triple = get_clang_target();
  driver::Driver drv("", target_triple, diags);

#if LLVM_MAJOR_VERSION >= 4
  if (target_triple == "x86_64-unknown-linux-gnu" || target_triple == "aarch64-unknown-linux-gnu")
    flags_cstr.push_back("-fno-jump-tables");
#endif

  drv.setTitle("bcc-clang-driver");
  drv.setCheckInputsExist(false);

  unique_ptr<driver::Compilation> compilation(drv.BuildCompilation(flags_cstr));
  if (!compilation)
    return -1;

  // expect exactly 1 job, otherwise error
  const driver::JobList &jobs = compilation->getJobs();
  if (jobs.size() != 1 || !isa<driver::Command>(*jobs.begin())) {
    SmallString<256> msg;
    llvm::raw_svector_ostream os(msg);
    jobs.Print(os, "; ", true);
    diags.Report(diag::err_fe_expected_compiler_job) << os.str();
    return -1;
  }

  const driver::Command &cmd = cast<driver::Command>(*jobs.begin());
  if (llvm::StringRef(cmd.getCreator().getName()) != "clang") {
    diags.Report(diag::err_fe_expected_clang_command);
    return -1;
  }

  // Initialize a compiler invocation object from the clang (-cc1) arguments.
  const llvm::opt::ArgStringList &ccargs = cmd.getArguments();

  if (flags_ & DEBUG_PREPROCESSOR) {
    llvm::errs() << "clang";
    for (auto arg : ccargs)
      llvm::errs() << " " << arg;
    llvm::errs() << "\n";
  }

  // pre-compilation pass for generating tracepoint structures
  CompilerInstance compiler0;
  CompilerInvocation &invocation0 = compiler0.getInvocation();
  if (!CreateFromArgs(invocation0, ccargs, diags))
    return -1;

  add_remapped_includes(invocation0);

  if (in_memory) {
    add_main_input(invocation0, main_path, &*main_buf);
  }
  invocation0.getFrontendOpts().DisableFree = false;

  compiler0.createDiagnostics(new IgnoringDiagConsumer());

  // capture the rewritten c file
  string out_str;
  llvm::raw_string_ostream os(out_str);
  TracepointFrontendAction tpact(os);
  compiler0.ExecuteAction(tpact); // ignore errors, they will be reported later
  unique_ptr<llvm::MemoryBuffer> out_buf = llvm::MemoryBuffer::getMemBuffer(out_str);

  // first pass
  CompilerInstance compiler1;
  CompilerInvocation &invocation1 = compiler1.getInvocation();
  if (!CreateFromArgs( invocation1, ccargs, diags))
    return -1;

  add_remapped_includes(invocation1);
  add_main_input(invocation1, main_path, &*out_buf);
  invocation1.getFrontendOpts().DisableFree = false;

  compiler1.createDiagnostics();

  // capture the rewritten c file
  string out_str1;
  llvm::raw_string_ostream os1(out_str1);
  BFrontendAction bact(os1, flags_, ts, id, main_path, prog_func_info, mod_src,
                       maps_ns, fake_fd_map, perf_events);
  if (!compiler1.ExecuteAction(bact))
    return -1;
  unique_ptr<llvm::MemoryBuffer> out_buf1 = llvm::MemoryBuffer::getMemBuffer(out_str1);

  // second pass, clear input and take rewrite buffer
  CompilerInstance compiler2;
  CompilerInvocation &invocation2 = compiler2.getInvocation();
  if (!CreateFromArgs(invocation2, ccargs, diags))
    return -1;

  add_remapped_includes(invocation2);
  add_main_input(invocation2, main_path, &*out_buf1);
  invocation2.getFrontendOpts().DisableFree = false;
  invocation2.getCodeGenOpts().DisableFree = false;
  // Resort to normal inlining. In -O0 the default is OnlyAlwaysInlining and
  // clang might add noinline attribute even for functions with inline hint.
  invocation2.getCodeGenOpts().setInlining(CodeGenOptions::NormalInlining);
  // suppress warnings in the 2nd pass, but bail out on errors (our fault)
  invocation2.getDiagnosticOpts().IgnoreWarnings = true;
  compiler2.createDiagnostics();

  EmitLLVMOnlyAction ir_act(&*ctx_);
  if (!compiler2.ExecuteAction(ir_act))
    return -1;
  *mod = ir_act.takeModule();

  return 0;
}
}  // namespace ebpf
