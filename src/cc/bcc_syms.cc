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

#include <cxxabi.h>
#include <cstring>
#include <fcntl.h>
#include <linux/elf.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

#include "syms.h"
#include "vendor/tinyformat.hpp"

ino_t ProcStat::getinode_() {
  struct stat s;
  return (!stat(procfs_.c_str(), &s)) ? s.st_ino : -1;
}

bool ProcStat::is_stale() {
  ino_t cur_inode = getinode_();
  return (cur_inode > 0) && (cur_inode != inode_);
}

ProcStat::ProcStat(int pid)
    : procfs_(tfm::format("/proc/%d/exe", pid)), inode_(getinode_()) {}

void KSyms::_add_symbol(const char *symname, uint64_t addr, void *p) {
  KSyms *ks = static_cast<KSyms *>(p);
  ks->syms_.emplace_back(symname, addr);
}

void KSyms::refresh() {
  if (syms_.empty()) {
    bcc_procutils_each_ksym(_add_symbol, this);
    std::sort(syms_.begin(), syms_.end());
  }
}

bool KSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym, bool demangle) {
  refresh();

  if (syms_.empty()) {
    sym->name = nullptr;
    sym->demangle_name = nullptr;
    sym->module = nullptr;
    sym->offset = 0x0;
    return false;
  }

  auto it = std::upper_bound(syms_.begin(), syms_.end(), Symbol("", addr)) - 1;
  sym->name = (*it).name.c_str();
  if (demangle)
    sym->demangle_name = sym->name;
  sym->module = "kernel";
  sym->offset = addr - (*it).addr;
  return true;
}

bool KSyms::resolve_name(const char *_unused, const char *name,
                         uint64_t *addr) {
  refresh();

  if (syms_.size() != symnames_.size()) {
    symnames_.clear();
    for (Symbol &sym : syms_) {
      symnames_[sym.name] = sym.addr;
    }
  }

  auto it = symnames_.find(name);
  if (it == symnames_.end())
    return false;

  *addr = it->second;
  return true;
}

ProcSyms::ProcSyms(int pid, struct bcc_symbol_option *option)
    : pid_(pid), procstat_(pid), mount_ns_instance_(new ProcMountNS(pid_)) {
  if (option)
    std::memcpy(&symbol_option_, option, sizeof(bcc_symbol_option));
  else
    symbol_option_ = {
      .use_debug_file = 1,
      .check_debug_file_crc = 1,
      .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
    };
  load_modules();
}

bool ProcSyms::load_modules() {
  return bcc_procutils_each_module(pid_, _add_module, this) == 0;
}

void ProcSyms::refresh() {
  modules_.clear();
  mount_ns_instance_.reset(new ProcMountNS(pid_));
  load_modules();
  procstat_.reset();
}

int ProcSyms::_add_module(const char *modname, uint64_t start, uint64_t end,
                          bool check_mount_ns, void *payload) {
  ProcSyms *ps = static_cast<ProcSyms *>(payload);
  auto it = std::find_if(
      ps->modules_.begin(), ps->modules_.end(),
      [=](const ProcSyms::Module &m) { return m.name_ == modname; });
  if (it == ps->modules_.end()) {
    auto module = Module(
        modname, check_mount_ns ? ps->mount_ns_instance_.get() : nullptr,
        &ps->symbol_option_);
    if (module.init())
      it = ps->modules_.insert(ps->modules_.end(), std::move(module));
    else
      return 0;
  }
  it->ranges_.emplace_back(start, end);

  return 0;
}

bool ProcSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym,
                            bool demangle) {
  if (procstat_.is_stale())
    refresh();

  sym->module = nullptr;
  sym->name = nullptr;
  sym->demangle_name = nullptr;
  sym->offset = 0x0;

  const char *original_module = nullptr;
  uint64_t offset;
  for (Module &mod : modules_) {
    if (mod.contains(addr, offset)) {
      bool res = mod.find_addr(offset, sym);
      if (demangle) {
        if (sym->name)
          sym->demangle_name =
              abi::__cxa_demangle(sym->name, nullptr, nullptr, nullptr);
        if (!sym->demangle_name)
          sym->demangle_name = sym->name;
      }
      // If we have a match, return right away. But if we don't have a match in
      // this module, we might have a match in the perf map (even though the
      // module itself doesn't have symbols). Wait until we see the perf map if
      // any, but keep the original module name for reporting.
      if (res) {
        // If we have already seen this module, report the original name rather
        // than the perf map name:
        if (original_module)
          sym->module = original_module;
        return res;
      } else if (mod.type_ != ModuleType::PERF_MAP) {
        // Record the module to which this symbol belongs, so that even if it's
        // later found using a perf map, we still report the right module name.
        original_module = mod.name_.c_str();
      }
    }
  }
  return false;
}

bool ProcSyms::resolve_name(const char *module, const char *name,
                            uint64_t *addr) {
  if (procstat_.is_stale())
    refresh();

  for (Module &mod : modules_) {
    if (mod.name_ == module)
      return mod.find_name(name, addr);
  }
  return false;
}

ProcSyms::Module::Module(const char *name, ProcMountNS *mount_ns,
                         struct bcc_symbol_option *option)
    : name_(name),
      loaded_(false),
      mount_ns_(mount_ns),
      symbol_option_(option),
      type_(ModuleType::UNKNOWN) {}

bool ProcSyms::Module::init() {
  ProcMountNSGuard g(mount_ns_);
  int elf_type = bcc_elf_get_type(name_.c_str());
  if (elf_type >= 0) {
    if (elf_type == ET_EXEC) {
      type_ = ModuleType::EXEC;
      return true;
    }
    if (elf_type == ET_DYN) {
      type_ = ModuleType::SO;
      return true;
    }
    return false;
  }

  if (bcc_is_perf_map(name_.c_str()) == 1) {
    type_ = ModuleType::PERF_MAP;
    return true;
  }

  return false;
}

int ProcSyms::Module::_add_symbol(const char *symname, uint64_t start,
                                  uint64_t size, void *p) {
  Module *m = static_cast<Module *>(p);
  auto res = m->symnames_.emplace(symname);
  m->syms_.emplace_back(&*(res.first), start, size);
  return 0;
}

void ProcSyms::Module::load_sym_table() {
  if (loaded_)
    return;
  loaded_ = true;

  ProcMountNSGuard g(mount_ns_);

  if (type_ == ModuleType::PERF_MAP)
    bcc_perf_map_foreach_sym(name_.c_str(), _add_symbol, this);
  if (type_ == ModuleType::EXEC || type_ == ModuleType::SO)
    bcc_elf_foreach_sym(name_.c_str(), _add_symbol, symbol_option_, this);

  std::sort(syms_.begin(), syms_.end());
}

bool ProcSyms::Module::contains(uint64_t addr, uint64_t &offset) const {
  for (const auto &range : ranges_)
    if (addr >= range.start && addr < range.end) {
      offset = type_ == ModuleType::SO ? addr - range.start : addr;
      return true;
    }
  return false;
}

bool ProcSyms::Module::find_name(const char *symname, uint64_t *addr) {
  load_sym_table();

  for (Symbol &s : syms_) {
    if (*(s.name) == symname) {
      *addr = type_ == ModuleType::SO ? start() + s.start : s.start;
      return true;
    }
  }
  return false;
}

bool ProcSyms::Module::find_addr(uint64_t offset, struct bcc_symbol *sym) {
  load_sym_table();

  sym->module = name_.c_str();
  sym->offset = offset;

  auto it = std::upper_bound(syms_.begin(), syms_.end(), Symbol(nullptr, offset, 0));
  if (it == syms_.begin())
    return false;

  // 'it' points to the symbol whose start address is strictly greater than
  // the address we're looking for. Start stepping backwards as long as the
  // current symbol is still below the desired address, and see if the end
  // of the current symbol (start + size) is above the desired address. Once
  // we have a matching symbol, return it. Note that simply looking at '--it'
  // is not enough, because symbols can be nested. For example, we could be
  // looking for offset 0x12 with the following symbols available:
  // SYMBOL   START   SIZE    END
  // goo      0x0     0x6     0x0 + 0x6 = 0x6
  // foo      0x6     0x10    0x6 + 0x10 = 0x16
  // bar      0x8     0x4     0x8 + 0x4 = 0xc
  // baz      0x16    0x10    0x16 + 0x10 = 0x26
  // The upper_bound lookup will return baz, and then going one symbol back
  // brings us to bar, which does not contain offset 0x12 and is nested inside
  // foo. Going back one more symbol brings us to foo, which contains 0x12
  // and is a match.
  // However, we also don't want to walk through the entire symbol list for
  // unknown / missing symbols. So we will break if we reach a function that
  // doesn't cover the function immediately before 'it', which means it is
  // not possibly a nested function containing the address we're looking for.
  --it;
  uint64_t limit = it->start;
  for (; offset >= it->start; --it) {
    if (offset < it->start + it->size) {
      sym->name = it->name->c_str();
      sym->offset = (offset - it->start);
      return true;
    }
    if (limit > it->start + it->size)
      break;
    // But don't step beyond begin()!
    if (it == syms_.begin())
      break;
  }

  return false;
}

extern "C" {

void *bcc_symcache_new(int pid, struct bcc_symbol_option *option) {
  if (pid < 0)
    return static_cast<void *>(new KSyms());
  return static_cast<void *>(new ProcSyms(pid, option));
}

void bcc_free_symcache(void *symcache, int pid) {
  if (pid < 0)
    delete static_cast<KSyms*>(symcache);
  else
    delete static_cast<ProcSyms*>(symcache);
}

void bcc_symbol_free_demangle_name(struct bcc_symbol *sym) {
  if (sym->demangle_name && (sym->demangle_name != sym->name))
    free(const_cast<char*>(sym->demangle_name));
}

int bcc_symcache_resolve(void *resolver, uint64_t addr,
                         struct bcc_symbol *sym) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  return cache->resolve_addr(addr, sym) ? 0 : -1;
}

int bcc_symcache_resolve_no_demangle(void *resolver, uint64_t addr,
                                     struct bcc_symbol *sym) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  return cache->resolve_addr(addr, sym, false) ? 0 : -1;
}

int bcc_symcache_resolve_name(void *resolver, const char *module,
                              const char *name, uint64_t *addr) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  return cache->resolve_name(module, name, addr) ? 0 : -1;
}

void bcc_symcache_refresh(void *resolver) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  cache->refresh();
}

struct mod_st {
  const char *name;
  uint64_t start;
};

static int _find_module(const char *modname, uint64_t start, uint64_t end, bool,
                        void *p) {
  struct mod_st *mod = (struct mod_st *)p;
  if (!strcmp(modname, mod->name)) {
    mod->start = start;
    return -1;
  }
  return 0;
}

int bcc_resolve_global_addr(int pid, const char *module, const uint64_t address,
                            uint64_t *global) {
  struct mod_st mod = {module, 0x0};
  if (bcc_procutils_each_module(pid, _find_module, &mod) < 0 ||
      mod.start == 0x0)
    return -1;

  *global = mod.start + address;
  return 0;
}

static int _sym_cb_wrapper(const char *symname, uint64_t addr, uint64_t,
                           void *payload) {
  SYM_CB cb = (SYM_CB) payload;
  return cb(symname, addr);
}

int bcc_foreach_function_symbol(const char *module, SYM_CB cb) {
  if (module == 0 || cb == 0)
    return -1;

  static struct bcc_symbol_option default_option = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
  };

  return bcc_elf_foreach_sym(
      module, _sym_cb_wrapper, &default_option, (void *)cb);
}

static int _find_sym(const char *symname, uint64_t addr, uint64_t,
                     void *payload) {
  struct bcc_symbol *sym = (struct bcc_symbol *)payload;
  if (!strcmp(sym->name, symname)) {
    sym->offset = addr;
    return -1;
  }
  return 0;
}

int bcc_resolve_symname(const char *module, const char *symname,
                        const uint64_t addr, int pid,
                        struct bcc_symbol_option *option,
                        struct bcc_symbol *sym) {
  uint64_t load_addr;
  static struct bcc_symbol_option default_option = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .use_symbol_type = BCC_SYM_ALL_TYPES,
  };

  if (module == NULL)
    return -1;

  memset(sym, 0, sizeof(bcc_symbol));

  if (strchr(module, '/')) {
    sym->module = strdup(module);
  } else {
    sym->module = bcc_procutils_which_so(module, pid);
  }

  if (sym->module == NULL)
    return -1;

  ProcMountNSGuard g(pid);

  if (bcc_elf_loadaddr(sym->module, &load_addr) < 0)
    goto invalid_module;

  sym->name = symname;
  sym->offset = addr;

  if (option == NULL)
    option = &default_option;

  if (sym->name && sym->offset == 0x0)
    if (bcc_elf_foreach_sym(sym->module, _find_sym, option, sym) < 0)
      goto invalid_module;

  if (sym->offset == 0x0)
    goto invalid_module;

  sym->offset = (sym->offset - load_addr);
  return 0;

invalid_module:
  if (sym->module) {
    ::free(const_cast<char*>(sym->module));
    sym->module = NULL;
  }
  return -1;
}

void *bcc_enter_mount_ns(int pid) {
  return static_cast<void *>(new ProcMountNSGuard(pid));
}

void bcc_exit_mount_ns(void **guard) {
  if (guard && *guard) {
    delete static_cast<ProcMountNSGuard *>(*guard);
    *guard = NULL;
  }
}
}
