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
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

bool KSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym) {
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

ProcSyms::ProcSyms(int pid) : pid_(pid), procstat_(pid) { load_modules(); }

bool ProcSyms::load_modules() {
  return bcc_procutils_each_module(pid_, _add_module, this) == 0;
}

void ProcSyms::refresh() {
  modules_.clear();
  load_modules();
  procstat_.reset();
}

int ProcSyms::_add_module(const char *modname, uint64_t start, uint64_t end,
                          void *payload) {
  ProcSyms *ps = static_cast<ProcSyms *>(payload);
  auto it = std::find_if(ps->modules_.begin(), ps->modules_.end(),
               [=](const ProcSyms::Module &m) { return m.name_ == modname; });
  if (it == ps->modules_.end())
    it = ps->modules_.insert(ps->modules_.end(), modname);
  it->ranges_.push_back(ProcSyms::Module::Range(start, end));
  return 0;
}

bool ProcSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym) {
  if (procstat_.is_stale())
    refresh();

  sym->module = nullptr;
  sym->name = nullptr;
  sym->demangle_name = nullptr;
  sym->offset = 0x0;

  const char *original_module = nullptr;
  for (Module &mod : modules_) {
    if (mod.contains(addr)) {
      bool res = mod.find_addr(addr, sym);
      if (sym->name) {
        sym->demangle_name = abi::__cxa_demangle(sym->name, nullptr, nullptr, nullptr);
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
      } else {
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

ProcSyms::Module::Module(const char *name)
  : name_(name) {
  is_so_ = bcc_elf_is_shared_obj(name) == 1;
}

int ProcSyms::Module::_add_symbol(const char *symname, uint64_t start,
                                  uint64_t end, int flags, void *p) {
  Module *m = static_cast<Module *>(p);
  auto res = m->symnames_.emplace(symname);
  m->syms_.emplace_back(&*(res.first), start, end, flags);
  return 0;
}

bool ProcSyms::Module::is_perf_map() const {
  return strstr(name_.c_str(), ".map") != nullptr;
}

void ProcSyms::Module::load_sym_table() {
  if (syms_.size())
    return;

  if (is_perf_map())
    bcc_perf_map_foreach_sym(name_.c_str(), _add_symbol, this);
  else
    bcc_elf_foreach_sym(name_.c_str(), _add_symbol, this);

  std::sort(syms_.begin(), syms_.end());
}

bool ProcSyms::Module::contains(uint64_t addr) const {
  for (const auto &range : ranges_) {
    if (addr >= range.start && addr < range.end)
      return true;
  }
  return false;
}

bool ProcSyms::Module::find_name(const char *symname, uint64_t *addr) {
  load_sym_table();

  for (Symbol &s : syms_) {
    if (*(s.name) == symname) {
      *addr = is_so() ? start() + s.start : s.start;
      return true;
    }
  }
  return false;
}

bool ProcSyms::Module::find_addr(uint64_t addr, struct bcc_symbol *sym) {
  uint64_t offset = is_so() ? (addr - start()) : addr;

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
  for (--it; offset >= it->start; --it) {
    if (offset < it->start + it->size) {
      sym->name = it->name->c_str();
      sym->offset = (offset - it->start);
      return true;
    }
    // But don't step beyond begin()!
    if (it == syms_.begin())
      break;
  }

  return false;
}

extern "C" {

void *bcc_symcache_new(int pid) {
  if (pid < 0)
    return static_cast<void *>(new KSyms());
  return static_cast<void *>(new ProcSyms(pid));
}

void bcc_free_symcache(void *symcache, int pid) {
  if (pid < 0)
    delete static_cast<KSyms*>(symcache);
  else
    delete static_cast<ProcSyms*>(symcache);
}

int bcc_symcache_resolve(void *resolver, uint64_t addr,
                         struct bcc_symbol *sym) {
  SymbolCache *cache = static_cast<SymbolCache *>(resolver);
  return cache->resolve_addr(addr, sym) ? 0 : -1;
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

static int _find_module(const char *modname, uint64_t start, uint64_t end,
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

static int _find_sym(const char *symname, uint64_t addr, uint64_t end,
                     int flags, void *payload) {
  struct bcc_symbol *sym = (struct bcc_symbol *)payload;
  // TODO: check for actual function symbol in flags
  if (!strcmp(sym->name, symname)) {
    sym->offset = addr;
    return -1;
  }
  return 0;
}

int bcc_find_symbol_addr(struct bcc_symbol *sym) {
  return bcc_elf_foreach_sym(sym->module, _find_sym, sym);
}

struct sym_search_t {
  struct bcc_symbol *syms;
  int start;
  int requested;
  int *actual;
};

// see <elf.h>
#define ELF_TYPE_IS_FUNCTION(flags) (((flags) & 0xf) == 2)

static int _list_sym(const char *symname, uint64_t addr, uint64_t end,
                     int flags, void *payload) {
  if (!ELF_TYPE_IS_FUNCTION(flags) || addr == 0)
    return 0;

  SYM_CB cb = (SYM_CB) payload;
  return cb(symname, addr);
}

int bcc_foreach_symbol(const char *module, SYM_CB cb) {
  if (module == 0 || cb == 0)
    return -1;

  return bcc_elf_foreach_sym(module, _list_sym, (void *)cb);
}

int bcc_resolve_symname(const char *module, const char *symname,
                        const uint64_t addr, int pid, struct bcc_symbol *sym) {
  uint64_t load_addr;

  sym->module = NULL;
  sym->name = NULL;
  sym->offset = 0x0;

  if (module == NULL)
    return -1;

  if (strchr(module, '/')) {
    sym->module = strdup(module);
  } else {
    sym->module = bcc_procutils_which_so(module, pid);
  }

  if (sym->module == NULL)
    return -1;

  if (bcc_elf_loadaddr(sym->module, &load_addr) < 0) {
    sym->module = NULL;
    return -1;
  }

  sym->name = symname;
  sym->offset = addr;

  if (sym->name && sym->offset == 0x0) {
    if (bcc_find_symbol_addr(sym) < 0)
      return -1;
  }

  if (sym->offset == 0x0)
    return -1;

  sym->offset = (sym->offset - load_addr);
  return 0;
}
}
