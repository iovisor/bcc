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
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>
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

#include <llvm/IR/Module.h>

#include "common.h"
#include "exception.h"
#include "kbuild_helper.h"
#include "b_frontend_action.h"
#include "loader.h"

using std::map;
using std::string;
using std::unique_ptr;
using std::vector;

namespace ebpf {

ClangLoader::ClangLoader(llvm::LLVMContext *ctx)
    : ctx_(ctx)
{}

ClangLoader::~ClangLoader() {}

int ClangLoader::parse(unique_ptr<llvm::Module> *mod,
                       unique_ptr<map<string, TableDesc>> *tables,
                       const string &file, bool in_memory) {
  using namespace clang;

  struct utsname un;
  uname(&un);
  char kdir[256];
  snprintf(kdir, sizeof(kdir), "%s/%s/build", KERNEL_MODULES_DIR, un.release);

  // clang needs to run inside the kernel dir
  DirStack dstack(kdir);
  if (!dstack.ok())
    return -1;

  string abs_file;
  if (in_memory) {
    abs_file = "<bcc-memory-buffer>";
  } else {
    if (file.substr(0, 1) == "/")
      abs_file = file;
    else
      abs_file = string(dstack.cwd()) + "/" + file;
  }

  vector<const char *> flags_cstr({"-O0", "-emit-llvm", "-I", dstack.cwd(),
                                   "-Wno-deprecated-declarations",
                                   "-x", "c", "-c", abs_file.c_str()});

  KBuildHelper kbuild_helper;
  vector<string> kflags;
  if (kbuild_helper.get_flags(un.release, &kflags))
    return -1;
  kflags.push_back("-include");
  kflags.push_back(BCC_INSTALL_PREFIX "/share/bcc/include/bcc/helpers.h");
  kflags.push_back("-I");
  kflags.push_back(BCC_INSTALL_PREFIX "/share/bcc/include");
  for (auto it = kflags.begin(); it != kflags.end(); ++it)
    flags_cstr.push_back(it->c_str());

  // set up the error reporting class
  IntrusiveRefCntPtr<DiagnosticOptions> diag_opts(new DiagnosticOptions());
  auto diag_client = new TextDiagnosticPrinter(llvm::errs(), &*diag_opts);

  IntrusiveRefCntPtr<DiagnosticIDs> DiagID(new DiagnosticIDs());
  DiagnosticsEngine diags(DiagID, &*diag_opts, diag_client);

  // set up the command line argument wrapper
  driver::Driver drv("", "x86_64-unknown-linux-gnu", diags);
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
  const driver::ArgStringList &ccargs = cmd.getArguments();

  // first pass
  auto invocation1 = make_unique<CompilerInvocation>();
  if (!CompilerInvocation::CreateFromArgs(*invocation1, const_cast<const char **>(ccargs.data()),
                                          const_cast<const char **>(ccargs.data()) + ccargs.size(), diags))
    return -1;

  if (in_memory) {
    invocation1->getPreprocessorOpts().addRemappedFile("<bcc-memory-buffer>",
                                                       llvm::MemoryBuffer::getMemBuffer(file).release());
    invocation1->getFrontendOpts().Inputs.clear();
    invocation1->getFrontendOpts().Inputs.push_back(FrontendInputFile("<bcc-memory-buffer>", IK_C));
  }
  invocation1->getFrontendOpts().DisableFree = false;

  CompilerInstance compiler1;
  compiler1.setInvocation(invocation1.release());
  compiler1.createDiagnostics();

  // capture the rewritten c file
  string out_str;
  llvm::raw_string_ostream os(out_str);
  BFrontendAction bact(os);
  if (!compiler1.ExecuteAction(bact))
    return -1;
  // this contains the open FDs
  *tables = bact.take_tables();

  // second pass, clear input and take rewrite buffer
  auto invocation2 = make_unique<CompilerInvocation>();
  if (!CompilerInvocation::CreateFromArgs(*invocation2, const_cast<const char **>(ccargs.data()),
                                          const_cast<const char **>(ccargs.data()) + ccargs.size(), diags))
    return -1;
  CompilerInstance compiler2;
  invocation2->getPreprocessorOpts().addRemappedFile("<bcc-memory-buffer>",
                                                     llvm::MemoryBuffer::getMemBuffer(out_str).release());
  invocation2->getFrontendOpts().Inputs.clear();
  invocation2->getFrontendOpts().Inputs.push_back(FrontendInputFile("<bcc-memory-buffer>", IK_C));
  invocation2->getFrontendOpts().DisableFree = false;
  // suppress warnings in the 2nd pass, but bail out on errors (our fault)
  invocation2->getDiagnosticOpts().IgnoreWarnings = true;
  compiler2.setInvocation(invocation2.release());
  compiler2.createDiagnostics();

  EmitLLVMOnlyAction ir_act(&*ctx_);
  if (!compiler2.ExecuteAction(ir_act))
    return -1;
  *mod = ir_act.takeModule();

  return 0;
}


}  // namespace ebpf
