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
#include <fcntl.h>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <linux/bpf.h>

#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IR/IRPrintingPasses.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm-c/Transforms/IPO.h>

#include "common.h"
#include "bcc_debug.h"
#include "frontends/b/loader.h"
#include "frontends/clang/loader.h"
#include "frontends/clang/b_frontend_action.h"
#include "bpf_module.h"
#include "exported_files.h"
#include "libbpf.h"

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

const string BPFModule::FN_PREFIX = BPF_FN_PREFIX;

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

BPFModule::BPFModule(unsigned flags, TableStorage *ts, bool rw_engine_enabled,
                     const std::string &maps_ns)
    : flags_(flags),
      rw_engine_enabled_(rw_engine_enabled && bpf_module_rw_engine_enabled()),
      used_b_loader_(false),
      ctx_(new LLVMContext),
      id_(std::to_string((uintptr_t)this)),
      maps_ns_(maps_ns),
      ts_(ts) {
  initialize_rw_engine();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFAsmPrinter();
#if LLVM_MAJOR_VERSION >= 6
  LLVMInitializeBPFAsmParser();
  if (flags & DEBUG_SOURCE)
    LLVMInitializeBPFDisassembler();
#endif
  LLVMLinkInMCJIT(); /* call empty function to force linking of MCJIT */
  if (!ts_) {
    local_ts_ = createSharedTableStorage();
    ts_ = &*local_ts_;
  }
  func_src_ = ebpf::make_unique<FuncSource>();
}

static StatusTuple unimplemented_sscanf(const char *, void *) {
  return StatusTuple(-1, "sscanf unimplemented");
}
static StatusTuple unimplemented_snprintf(char *, size_t, const void *) {
  return StatusTuple(-1, "snprintf unimplemented");
}

BPFModule::~BPFModule() {
  for (auto &v : tables_) {
    v->key_sscanf = unimplemented_sscanf;
    v->leaf_sscanf = unimplemented_sscanf;
    v->key_snprintf = unimplemented_snprintf;
    v->leaf_snprintf = unimplemented_snprintf;
  }

  if (!rw_engine_enabled_) {
    for (auto section : sections_)
      delete[] get<0>(section.second);
  }

  engine_.reset();
  cleanup_rw_engine();
  ctx_.reset();
  func_src_.reset();

  ts_->DeletePrefix(Path({id_}));
}

// load an entire c file as a module
int BPFModule::load_cfile(const string &file, bool in_memory, const char *cflags[], int ncflags) {
  ClangLoader clang_loader(&*ctx_, flags_);
  if (clang_loader.parse(&mod_, *ts_, file, in_memory, cflags, ncflags, id_,
                         *func_src_, mod_src_, maps_ns_))
    return -1;
  return 0;
}

// NOTE: this is a duplicate of the above, but planning to deprecate if we
// settle on clang as the frontend

// Load in a pre-built list of functions into the initial Module object, then
// build an ExecutionEngine.
int BPFModule::load_includes(const string &text) {
  ClangLoader clang_loader(&*ctx_, flags_);
  if (clang_loader.parse(&mod_, *ts_, text, true, nullptr, 0, "", *func_src_,
                         mod_src_, ""))
    return -1;
  return 0;
}

void BPFModule::annotate_light() {
  for (auto fn = mod_->getFunctionList().begin(); fn != mod_->getFunctionList().end(); ++fn)
    if (!fn->hasFnAttribute(Attribute::NoInline))
      fn->addFnAttr(Attribute::AlwaysInline);

  size_t id = 0;
  Path path({id_});
  for (auto it = ts_->lower_bound(path), up = ts_->upper_bound(path); it != up; ++it) {
    TableDesc &table = it->second;
    tables_.push_back(&it->second);
    table_names_[table.name] = id++;
  }
}

void BPFModule::dump_ir(Module &mod) {
  legacy::PassManager PM;
  PM.add(createPrintModulePass(errs()));
  PM.run(mod);
}

int BPFModule::run_pass_manager(Module &mod) {
  if (verifyModule(mod, &errs())) {
    if (flags_ & DEBUG_LLVM_IR)
      dump_ir(mod);
    return -1;
  }

  legacy::PassManager PM;
  PassManagerBuilder PMB;
  PMB.OptLevel = 3;
  PM.add(createFunctionInliningPass());
  /*
   * llvm < 4.0 needs
   * PM.add(createAlwaysInlinerPass());
   * llvm >= 4.0 needs
   * PM.add(createAlwaysInlinerLegacyPass());
   * use below 'stable' workaround
   */
  LLVMAddAlwaysInlinerPass(reinterpret_cast<LLVMPassManagerRef>(&PM));
  PMB.populateModulePassManager(PM);
  if (flags_ & DEBUG_LLVM_IR)
    PM.add(createPrintModulePass(outs()));
  PM.run(mod);
  return 0;
}

int BPFModule::finalize() {
  Module *mod = &*mod_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> tmp_sections,
      *sections_p;

  mod->setTargetTriple("bpf-pc-linux");
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  mod->setDataLayout("e-m:e-p:64:64-i64:64-n32:64-S128");
#else
  mod->setDataLayout("E-m:e-p:64:64-i64:64-n32:64-S128");
#endif
  sections_p = rw_engine_enabled_ ? &sections_ : &tmp_sections;

  string err;
  EngineBuilder builder(move(mod_));
  builder.setErrorStr(&err);
  builder.setMCJITMemoryManager(ebpf::make_unique<MyMemoryManager>(sections_p));
  builder.setMArch("bpf");
  builder.setUseOrcMCJITReplacement(false);
  engine_ = unique_ptr<ExecutionEngine>(builder.create());
  if (!engine_) {
    fprintf(stderr, "Could not create ExecutionEngine: %s\n", err.c_str());
    return -1;
  }

  if (flags_ & DEBUG_SOURCE)
    engine_->setProcessAllSections(true);

  if (int rc = run_pass_manager(*mod))
    return rc;

  engine_->finalizeObject();

  if (flags_ & DEBUG_SOURCE) {
    SourceDebugger src_debugger(mod, *sections_p, FN_PREFIX, mod_src_,
                                src_dbg_fmap_);
    src_debugger.dump();
  }

  if (!rw_engine_enabled_) {
    // Setup sections_ correctly and then free llvm internal memory
    for (auto section : tmp_sections) {
      auto fname = section.first;
      uintptr_t size = get<1>(section.second);
      uint8_t *tmp_p = NULL;
      // Only copy data for non-map sections
      if (strncmp("maps/", section.first.c_str(), 5)) {
        uint8_t *addr = get<0>(section.second);
        tmp_p = new uint8_t[size];
        memcpy(tmp_p, addr, size);
      }
      sections_[fname] = make_tuple(tmp_p, size);
    }
    engine_.reset();
    ctx_.reset();
  }

  // give functions an id
  for (auto section : sections_)
    if (!strncmp(FN_PREFIX.c_str(), section.first.c_str(), FN_PREFIX.size()))
      function_names_.push_back(section.first);

  return 0;
}

size_t BPFModule::num_functions() const {
  return function_names_.size();
}

const char * BPFModule::function_name(size_t id) const {
  if (id >= function_names_.size())
    return nullptr;
  return function_names_[id].c_str() + FN_PREFIX.size();
}

uint8_t * BPFModule::function_start(size_t id) const {
  if (id >= function_names_.size())
    return nullptr;
  auto section = sections_.find(function_names_[id]);
  if (section == sections_.end())
    return nullptr;
  return get<0>(section->second);
}

uint8_t * BPFModule::function_start(const string &name) const {
  auto section = sections_.find(FN_PREFIX + name);
  if (section == sections_.end())
    return nullptr;

  return get<0>(section->second);
}

const char * BPFModule::function_source(const string &name) const {
  return func_src_->src(name);
}

const char * BPFModule::function_source_rewritten(const string &name) const {
  return func_src_->src_rewritten(name);
}

int BPFModule::annotate_prog_tag(const string &name, int prog_fd,
                                 struct bpf_insn *insns, int prog_len) {
  unsigned long long tag1, tag2;
  int err;

  err = bpf_prog_compute_tag(insns, prog_len, &tag1);
  if (err)
    return err;
  err = bpf_prog_get_tag(prog_fd, &tag2);
  if (err)
    return err;
  if (tag1 != tag2) {
    fprintf(stderr, "prog tag mismatch %llx %llx\n", tag1, tag2);
    return -1;
  }

  err = mkdir(BCC_PROG_TAG_DIR, 0777);
  if (err && errno != EEXIST) {
    fprintf(stderr, "cannot create " BCC_PROG_TAG_DIR "\n");
    return -1;
  }

  char buf[128];
  ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx", tag1);
  err = mkdir(buf, 0777);
  if (err && errno != EEXIST) {
    fprintf(stderr, "cannot create %s\n", buf);
    return -1;
  }

  ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx/%s.c",
             tag1, name.data());
  FileDesc fd(open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0644));
  if (fd < 0) {
    fprintf(stderr, "cannot create %s\n", buf);
    return -1;
  }

  const char *src = function_source(name);
  write(fd, src, strlen(src));

  ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx/%s.rewritten.c",
             tag1, name.data());
  fd = open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) {
    fprintf(stderr, "cannot create %s\n", buf);
    return -1;
  }

  src = function_source_rewritten(name);
  write(fd, src, strlen(src));

  if (!src_dbg_fmap_[name].empty()) {
    ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx/%s.dis.txt",
               tag1, name.data());
    fd = open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
      fprintf(stderr, "cannot create %s\n", buf);
      return -1;
    }

    const char *src = src_dbg_fmap_[name].c_str();
    write(fd, src, strlen(src));
  }

  return 0;
}

size_t BPFModule::function_size(size_t id) const {
  if (id >= function_names_.size())
    return 0;
  auto section = sections_.find(function_names_[id]);
  if (section == sections_.end())
    return 0;
  return get<1>(section->second);
}

size_t BPFModule::function_size(const string &name) const {
  auto section = sections_.find(FN_PREFIX + name);
  if (section == sections_.end())
    return 0;

  return get<1>(section->second);
}

char * BPFModule::license() const {
  auto section = sections_.find("license");
  if (section == sections_.end())
    return nullptr;

  return (char *)get<0>(section->second);
}

unsigned BPFModule::kern_version() const {
  auto section = sections_.find("version");
  if (section == sections_.end())
    return 0;

  return *(unsigned *)get<0>(section->second);
}

size_t BPFModule::num_tables() const { return tables_.size(); }

size_t BPFModule::table_id(const string &name) const {
  auto it = table_names_.find(name);
  if (it == table_names_.end()) return ~0ull;
  return it->second;
}

int BPFModule::table_fd(const string &name) const {
  return table_fd(table_id(name));
}

int BPFModule::table_fd(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->fd;
}

int BPFModule::table_type(const string &name) const {
  return table_type(table_id(name));
}

int BPFModule::table_type(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->type;
}

size_t BPFModule::table_max_entries(const string &name) const {
  return table_max_entries(table_id(name));
}

size_t BPFModule::table_max_entries(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->max_entries;
}

int BPFModule::table_flags(const string &name) const {
  return table_flags(table_id(name));
}

int BPFModule::table_flags(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->flags;
}

const char * BPFModule::table_name(size_t id) const {
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->name.c_str();
}

const char * BPFModule::table_key_desc(size_t id) const {
  if (used_b_loader_) return nullptr;
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->key_desc.c_str();
}

const char * BPFModule::table_key_desc(const string &name) const {
  return table_key_desc(table_id(name));
}

const char * BPFModule::table_leaf_desc(size_t id) const {
  if (used_b_loader_) return nullptr;
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->leaf_desc.c_str();
}

const char * BPFModule::table_leaf_desc(const string &name) const {
  return table_leaf_desc(table_id(name));
}
size_t BPFModule::table_key_size(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->key_size;
}
size_t BPFModule::table_key_size(const string &name) const {
  return table_key_size(table_id(name));
}

size_t BPFModule::table_leaf_size(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->leaf_size;
}
size_t BPFModule::table_leaf_size(const string &name) const {
  return table_leaf_size(table_id(name));
}

struct TableIterator {
  TableIterator(size_t key_size, size_t leaf_size)
      : key(new uint8_t[key_size]), leaf(new uint8_t[leaf_size]) {
  }
  unique_ptr<uint8_t[]> key;
  unique_ptr<uint8_t[]> leaf;
  uint8_t keyb[512];
};

int BPFModule::table_key_printf(size_t id, char *buf, size_t buflen, const void *key) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.key_snprintf(buf, buflen, key);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_printf(size_t id, char *buf, size_t buflen, const void *leaf) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.leaf_snprintf(buf, buflen, leaf);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_key_scanf(size_t id, const char *key_str, void *key) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.key_sscanf(key_str, key);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_scanf(size_t id, const char *leaf_str, void *leaf) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.leaf_sscanf(leaf_str, leaf);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

// load a B file, which comes in two parts
int BPFModule::load_b(const string &filename, const string &proto_filename) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (filename.empty() || proto_filename.empty()) {
    fprintf(stderr, "Invalid filenames\n");
    return -1;
  }

  // Helpers are inlined in the following file (C). Load the definitions and
  // pass the partially compiled module to the B frontend to continue with.
  auto helpers_h = ExportedFiles::headers().find("/virtual/include/bcc/helpers.h");
  if (helpers_h == ExportedFiles::headers().end()) {
    fprintf(stderr, "Internal error: missing bcc/helpers.h");
    return -1;
  }
  if (int rc = load_includes(helpers_h->second))
    return rc;

  BLoader b_loader(flags_);
  used_b_loader_ = true;
  if (int rc = b_loader.parse(&*mod_, filename, proto_filename, *ts_, id_,
                              maps_ns_))
    return rc;
  if (rw_engine_enabled_) {
    if (int rc = annotate())
      return rc;
  } else {
    annotate_light();
  }
  if (int rc = finalize())
    return rc;
  return 0;
}

// load a C file
int BPFModule::load_c(const string &filename, const char *cflags[], int ncflags) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (filename.empty()) {
    fprintf(stderr, "Invalid filename\n");
    return -1;
  }
  if (int rc = load_cfile(filename, false, cflags, ncflags))
    return rc;
  if (rw_engine_enabled_) {
    if (int rc = annotate())
      return rc;
  } else {
    annotate_light();
  }
  if (int rc = finalize())
    return rc;
  return 0;
}

// load a C text string
int BPFModule::load_string(const string &text, const char *cflags[], int ncflags) {
  if (!sections_.empty()) {
    fprintf(stderr, "Program already initialized\n");
    return -1;
  }
  if (int rc = load_cfile(text, true, cflags, ncflags))
    return rc;
  if (rw_engine_enabled_) {
    if (int rc = annotate())
      return rc;
  } else {
    annotate_light();
  }

  if (int rc = finalize())
    return rc;
  return 0;
}

} // namespace ebpf
