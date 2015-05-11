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

#include <clang/Basic/FileManager.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/CodeGen/BackendUtil.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>
#include <clang/Driver/Job.h>
#include <clang/Driver/Tool.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/CompilerInvocation.h>
#include <clang/Frontend/FrontendDiagnostic.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <clang/FrontendTool/Utils.h>
#include "clang/Parse/ParseAST.h"

#include <llvm/ADT/STLExtras.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include "exception.h"
#include "parser.h"
#include "type_check.h"
#include "codegen_llvm.h"
#include "bpf_program.h"

#define KERNEL_MODULES_DIR "/lib/modules"

// This is temporary, to be removed in the next commit
#define HELPER_FILE "../../src/cc/bitops.c"

namespace ebpf {

using std::get;
using std::make_tuple;
using std::map;
using std::move;
using std::string;
using std::tuple;
using std::unique_ptr;
using std::vector;
using namespace llvm;

// Snooping class to remember the sections as the JIT creates them
class MyMemoryManager : public SectionMemoryManager {
 public:

  explicit MyMemoryManager(map<string, tuple<uint8_t *, uintptr_t>> *sections)
      : sections_(sections) {
  }

  virtual ~MyMemoryManager() {}
  uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName) override {
    uint8_t *Addr = SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID, SectionName);
    //printf("allocateCodeSection: %s Addr %p Size %ld Alignment %d SectionID %d\n",
    //       SectionName.str().c_str(), (void *)Addr, Size, Alignment, SectionID);
    (*sections_)[SectionName.str()] = make_tuple(Addr, Size);
    return Addr;
  }
  uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID, StringRef SectionName,
                               bool isReadOnly) override {
    uint8_t *Addr = SectionMemoryManager::allocateDataSection(Size, Alignment, SectionID, SectionName, isReadOnly);
    //printf("allocateDataSection: %s Addr %p Size %ld Alignment %d SectionID %d RO %d\n",
    //       SectionName.str().c_str(), (void *)Addr, Size, Alignment, SectionID, isReadOnly);
    (*sections_)[SectionName.str()] = make_tuple(Addr, Size);
    return Addr;
  }
  map<string, tuple<uint8_t *, uintptr_t>> *sections_;
};

BPFProgram::BPFProgram(unsigned flags)
    : flags_(flags), ctx_(new LLVMContext) {
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
  LLVMLinkInMCJIT(); /* call empty function to force linking of MCJIT */
}

BPFProgram::~BPFProgram() {
  engine_.reset();
  ctx_.reset();
}

int BPFProgram::parse() {
  int rc;

  proto_parser_ = make_unique<ebpf::cc::Parser>(proto_filename_);
  rc = proto_parser_->parse();
  if (rc) {
    fprintf(stderr, "In file: %s\n", filename_.c_str());
    return rc;
  }

  parser_ = make_unique<ebpf::cc::Parser>(filename_);
  rc = parser_->parse();
  if (rc) {
    fprintf(stderr, "In file: %s\n", filename_.c_str());
    return rc;
  }

  //ebpf::cc::Printer printer(stderr);
  //printer.visit(parser_->root_node_);

  ebpf::cc::TypeCheck type_check(parser_->scopes_.get(), proto_parser_->scopes_.get(), parser_->pragmas_);
  auto ret = type_check.visit(parser_->root_node_);
  if (get<0>(ret) != 0 || get<1>(ret).size()) {
    fprintf(stderr, "Type error @line=%d: %s\n", get<0>(ret), get<1>(ret).c_str());
    exit(1);
  }

  codegen_ = ebpf::make_unique<ebpf::cc::CodegenLLVM>(mod_, parser_->scopes_.get(), proto_parser_->scopes_.get());
  ret = codegen_->visit(parser_->root_node_);
  if (get<0>(ret) != 0 || get<1>(ret).size()) {
    fprintf(stderr, "Codegen error @line=%d: %s\n", get<0>(ret), get<1>(ret).c_str());
    return get<0>(ret);
  }

  return 0;
}

// Helper with pushd/popd semantics
class DirStack {
 public:
  explicit DirStack(const char *dst) : ok_(false) {
    if (getcwd(cwd_, sizeof(cwd_)) == NULL) {
      ::perror("getcwd");
      return;
    }
    if (::chdir(dst)) {
      fprintf(stderr, "chdir(%s): %s\n", dst, strerror(errno));
      return;
    }
    ok_ = true;
  }
  ~DirStack() {
    if (!ok_) return;
    if (::chdir(cwd_)) {
      fprintf(stderr, "chdir(%s): %s\n", cwd_, strerror(errno));
    }
  }
  bool ok() const { return ok_; }
  const char * cwd() const { return cwd_; }
 private:
  bool ok_;
  char cwd_[256];
};

struct FileDeleter {
  void operator() (FILE *fp) {
    fclose(fp);
  }
};
typedef std::unique_ptr<FILE, FileDeleter> FILEPtr;

// Scoped class to manage the creation/deletion of tmpdirs
class TmpDir {
 public:
  explicit TmpDir(const string &prefix = "/tmp/bcc-")
      : ok_(false), prefix_(prefix) {
    prefix_ += "XXXXXX";
    if (::mkdtemp((char *)prefix.data()) == NULL)
      ::perror("mkdtemp");
    else
      ok_ = true;
  }
  ~TmpDir() {
    auto fn = [] (const char *path, const struct stat *, int) -> int {
      return ::remove(path);
    };
    if (::ftw(prefix_.c_str(), fn, 20) < 0)
      ::perror("ftw");
    else
      ::remove(prefix_.c_str());
  }
  bool ok() const { return ok_; }
  const string & str() const { return prefix_; }
 private:
  bool ok_;
  string prefix_;
};

// Compute the kbuild flags for the currently running kernel
// Do this by:
//   1. Create temp Makefile with stub dummy.c
//   2. Run module build on that makefile, saving the computed flags to a file
//   3. Cache the file for fast flag lookup in subsequent runs
//  Note: Depending on environment, different cache locations may be desired. In
//  case we eventually support non-root user programs, cache in $HOME.

// Makefile helper for kbuild_flags
static int learn_flags(const string &tmpdir, const char *uname_release, const char *cachefile) {
  {
    // Create a kbuild file to generate the flags
    string makefile = tmpdir + "/Makefile";
    FILEPtr mf(::fopen(makefile.c_str(), "w"));
    if (!mf)
      return -1;
    fprintf(&*mf, "obj-y := dummy.o\n");
    fprintf(&*mf, "CACHEDIR=$(dir %s)\n", cachefile);
    fprintf(&*mf, "$(CACHEDIR):\n");
    fprintf(&*mf, "\t@mkdir -p $(CACHEDIR)\n");
    fprintf(&*mf, "$(obj)/%%.o: $(src)/%%.c $(CACHEDIR)\n");
    fprintf(&*mf, "\t@echo -n \"$(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) "
                    "-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \" > %s\n", cachefile);
  }
  {
    string cfile = tmpdir + "/dummy.c";
    FILEPtr cf(::fopen(cfile.c_str(), "w"));
    if (!cf)
      return -1;
  }
  string cmd = "make -s";
  cmd += " -C " KERNEL_MODULES_DIR "/" + string(uname_release) + "/build";
  cmd += " M=" + tmpdir + " dummy.o";
  int rc = ::system(cmd.c_str());
  if (rc < 0) {
    ::perror("system");
    return -1;
  }
  return ::open(cachefile, O_RDONLY);
}

// read the flags from cache or learn
int BPFProgram::kbuild_flags(const char *uname_release, vector<string> *cflags) {
  char cachefile[256];
  char *home = ::getenv("HOME");
  if (home)
    snprintf(cachefile, sizeof(cachefile), "%s/.cache/bcc/%s.flags", home, uname_release);
  else
    snprintf(cachefile, sizeof(cachefile), "/var/run/bcc/%s.flags", uname_release);
  int cachefd = ::open(cachefile, O_RDONLY);
  if (cachefd < 0) {
    TmpDir tmpdir;
    if (!tmpdir.ok())
      return -1;
    cachefd = learn_flags(tmpdir.str(), uname_release, cachefile);
    if (cachefd < 0)
      return -1;
  }
  FILEPtr f(::fdopen(cachefd, "r"));
  size_t len = 0;
  char *line = NULL;
  ssize_t nread;
  while ((nread = getdelim(&line, &len, ' ', &*f)) >= 0) {
    if (nread == 0 || (nread == 1 && line[0] == ' ')) continue;
    if (line[nread - 1] == ' ')
      --nread;
    cflags->push_back(string(line, nread));
  }
  free(line);
  return 0;
}

int BPFProgram::load_helper(unique_ptr<llvm::Module> *mod) {
  using namespace clang;

  struct utsname un;
  uname(&un);
  char kdir[256];
  snprintf(kdir, sizeof(kdir), "%s/%s/build", KERNEL_MODULES_DIR, un.release);

  DirStack dstack(kdir);
  if (!dstack.ok())
    return -1;

  string file = string(dstack.cwd()) + "/" HELPER_FILE;
  vector<const char *> flags_cstr({"-fsyntax-only", "-emit-llvm", "-o", "/dev/null",
                                   "-c", file.c_str()});

  vector<string> kflags;
  if (kbuild_flags(un.release, &kflags))
    return -1;
  for (auto it = kflags.begin(); it != kflags.end(); ++it)
    flags_cstr.push_back(it->c_str());

  IntrusiveRefCntPtr<DiagnosticOptions> diag_opts(new DiagnosticOptions());
  auto diag_client = new TextDiagnosticPrinter(llvm::errs(), &*diag_opts);

  IntrusiveRefCntPtr<DiagnosticIDs> DiagID(new DiagnosticIDs());
  DiagnosticsEngine diags(DiagID, &*diag_opts, diag_client);

  driver::Driver drv("", "x86_64-unknown-linux-gnu", diags);
  drv.setTitle("bcc-clang-driver");
  drv.setCheckInputsExist(false);

  unique_ptr<driver::Compilation> compilation(drv.BuildCompilation(flags_cstr));
  if (!compilation)
    return 0;

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
  auto invocation = make_unique<CompilerInvocation>();
  CompilerInvocation::CreateFromArgs(*invocation, const_cast<const char **>(ccargs.data()),
                                     const_cast<const char **>(ccargs.data()) + ccargs.size(), diags);

  // Show the invocation, with -v.
  if (invocation->getHeaderSearchOpts().Verbose)
    jobs.Print(llvm::errs(), "\n", true);

  // Create a compiler instance to handle the actual work.
  CompilerInstance compiler;
  compiler.setInvocation(invocation.release());

  // Create the compilers actual diagnostics engine.
  compiler.createDiagnostics();
  if (!compiler.hasDiagnostics())
    return -1;

  // Create and execute the frontend to generate an LLVM bitcode module.
  EmitLLVMOnlyAction act(&*ctx_);
  if (!compiler.ExecuteAction(act))
    return -1;

  *mod = act.takeModule();

  return 0;
}

// Load in a pre-built list of functions into the initial Module object, then
// build an ExecutionEngine.
int BPFProgram::init_engine() {
  unique_ptr<Module> mod;
  if (load_helper(&mod))
    return -1;
  mod_ = &*mod;

  mod_->setDataLayout("e-m:e-i64:64-f80:128-n8:16:32:64-S128");
  mod_->setTargetTriple("bpf-pc-linux");

  for (auto fn = mod_->getFunctionList().begin(); fn != mod_->getFunctionList().end(); ++fn)
    fn->addFnAttr(Attribute::AlwaysInline);

  string err;
  engine_ = unique_ptr<ExecutionEngine>(EngineBuilder(move(mod))
      .setErrorStr(&err)
      .setMCJITMemoryManager(make_unique<MyMemoryManager>(&sections_))
      .setMArch("bpf")
      .create());
  if (!engine_) {
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", err.c_str());
    return -1;
  }

  return 0;
}

void BPFProgram::dump_ir() {
  legacy::PassManager PM;
  PM.add(createPrintModulePass(outs()));
  PM.run(*mod_);
}

int BPFProgram::finalize() {
  if (verifyModule(*mod_, &errs())) {
    if (flags_ & 1)
      dump_ir();
    return -1;
  }

  legacy::PassManager PM;
  PassManagerBuilder PMB;
  PMB.OptLevel = 3;
  PM.add(createFunctionInliningPass());
  PM.add(createAlwaysInlinerPass());
  PMB.populateModulePassManager(PM);
  if (flags_ & 1)
    PM.add(createPrintModulePass(outs()));
  PM.run(*mod_);

  engine_->finalizeObject();

  return 0;
}

uint8_t * BPFProgram::start(const string &name) const {
  auto section = sections_.find("." + name);
  if (section == sections_.end())
    return nullptr;

  return get<0>(section->second);
}

size_t BPFProgram::size(const string &name) const {
  auto section = sections_.find("." + name);
  if (section == sections_.end())
    return 0;

  return get<1>(section->second);
}

char * BPFProgram::license() const {
  auto section = sections_.find("license");
  if (section == sections_.end())
    return nullptr;

  return (char *)get<0>(section->second);
}

int BPFProgram::table_fd(const string &name) const {
  return codegen_->get_table_fd(name);
}

int BPFProgram::load(const string &filename, const string &proto_filename) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  filename_ = filename;
  proto_filename_ = proto_filename;
  if (int rc = init_engine())
    return rc;
  if (int rc = parse())
    return rc;
  if (int rc = finalize())
    return rc;
  return 0;
}

} // namespace ebpf
