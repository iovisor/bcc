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
#include "common.h"
#include "vendor/tinyformat.hpp"

#include "syms.h"

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

  std::vector<Symbol>::iterator it;

  if (syms_.empty())
    goto unknown_symbol;

  it = std::upper_bound(syms_.begin(), syms_.end(), Symbol("", addr));
  if (it != syms_.begin()) {
    it--;
    sym->name = (*it).name.c_str();
    if (demangle)
      sym->demangle_name = sym->name;
    sym->module = "kernel";
    sym->offset = addr - (*it).addr;
    return true;
  }

unknown_symbol:
  memset(sym, 0, sizeof(struct bcc_symbol));
  return false;
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

int ProcSyms::_add_load_sections(uint64_t v_addr, uint64_t mem_sz,
                                 uint64_t file_offset, void *payload) {
  auto module = static_cast<Module *>(payload);
  module->ranges_.emplace_back(v_addr, v_addr + mem_sz, file_offset);
  return 0;
}

void ProcSyms::load_exe() {
  std::string exe = ebpf::get_pid_exe(pid_);
  Module module(exe.c_str(), mount_ns_instance_.get(), &symbol_option_);

  if (module.type_ != ModuleType::EXEC)
    return;

  ProcMountNSGuard g(mount_ns_instance_.get());

  bcc_elf_foreach_load_section(exe.c_str(), &_add_load_sections, &module);

  if (!module.ranges_.empty())
    modules_.emplace_back(std::move(module));
}

void ProcSyms::load_modules() {
  load_exe();
  bcc_procutils_each_module(pid_, _add_module, this);
}

void ProcSyms::refresh() {
  modules_.clear();
  mount_ns_instance_.reset(new ProcMountNS(pid_));
  load_modules();
  procstat_.reset();
}

int ProcSyms::_add_module(const char *modname, uint64_t start, uint64_t end,
                          uint64_t offset, bool check_mount_ns, void *payload) {
  ProcSyms *ps = static_cast<ProcSyms *>(payload);
  auto it = std::find_if(
      ps->modules_.begin(), ps->modules_.end(),
      [=](const ProcSyms::Module &m) { return m.name_ == modname; });
  if (it == ps->modules_.end()) {
    auto module = Module(
        modname, check_mount_ns ? ps->mount_ns_instance_.get() : nullptr,
        &ps->symbol_option_);

    // pid/maps doesn't account for file_offset of text within the ELF.
    // It only gives the mmap offset. We need the real offset for symbol
    // lookup.
    if (module.type_ == ModuleType::SO) {
      if (bcc_elf_get_text_scn_info(modname, &module.elf_so_addr_,
                                    &module.elf_so_offset_) < 0) {
        fprintf(stderr, "WARNING: Couldn't find .text section in %s\n", modname);
        fprintf(stderr, "WARNING: BCC can't handle sym look ups for %s", modname);
      }
    }

    if (!bcc_is_perf_map(modname) || module.type_ != ModuleType::UNKNOWN)
      // Always add the module even if we can't read it, so that we could
      // report correct module name. Unless it's a perf map that we only
      // add readable ones.
      it = ps->modules_.insert(ps->modules_.end(), std::move(module));
    else
      return 0;
  }
  it->ranges_.emplace_back(start, end, offset);
  // perf-PID map is added last. We try both inside the Process's mount
  // namespace + chroot, and in global /tmp. Make sure we only add one.
  if (it->type_ == ModuleType::PERF_MAP)
    return -1;

  return 0;
}

bool ProcSyms::resolve_addr(uint64_t addr, struct bcc_symbol *sym,
                            bool demangle) {
  if (procstat_.is_stale())
    refresh();

  memset(sym, 0, sizeof(struct bcc_symbol));

  const char *original_module = nullptr;
  uint64_t offset;
  bool only_perf_map = false;
  for (Module &mod : modules_) {
    if (only_perf_map && (mod.type_ != ModuleType::PERF_MAP))
      continue;
    if (mod.contains(addr, offset)) {
      if (mod.find_addr(offset, sym)) {
        if (demangle) {
          if (sym->name && (!strncmp(sym->name, "_Z", 2) || !strncmp(sym->name, "___Z", 4)))
            sym->demangle_name =
                abi::__cxa_demangle(sym->name, nullptr, nullptr, nullptr);
          if (!sym->demangle_name)
            sym->demangle_name = sym->name;
        }
        return true;
      } else if (mod.type_ != ModuleType::PERF_MAP) {
        // In this case, we found the address in the range of a module, but
        // not able to find a symbol of that address in the module.
        // Thus, we would try to find the address in perf map, and
        // save the module's name in case we will need it later.
        original_module = mod.name_.c_str();
        only_perf_map = true;
      }
    }
  }
  // If we didn't find the symbol anywhere, the module name is probably
  // set to be the perf map's name as it would be the last we tried.
  // In this case, if we have found the address previously in a module,
  // report the saved original module name instead.
  if (original_module)
    sym->module = original_module;
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
      type_(ModuleType::UNKNOWN) {
  ProcMountNSGuard g(mount_ns_);
  int elf_type = bcc_elf_get_type(name_.c_str());
  // The Module is an ELF file
  if (elf_type >= 0) {
    if (elf_type == ET_EXEC)
      type_ = ModuleType::EXEC;
    else if (elf_type == ET_DYN)
      type_ = ModuleType::SO;
    return;
  }
  // Other symbol files
  if (bcc_is_valid_perf_map(name_.c_str()) == 1)
    type_ = ModuleType::PERF_MAP;
  else if (bcc_elf_is_vdso(name_.c_str()) == 1)
    type_ = ModuleType::VDSO;

  // Will be stored later
  elf_so_offset_ = 0;
  elf_so_addr_ = 0;
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

  if (type_ == ModuleType::UNKNOWN)
    return;

  ProcMountNSGuard g(mount_ns_);

  if (type_ == ModuleType::PERF_MAP)
    bcc_perf_map_foreach_sym(name_.c_str(), _add_symbol, this);
  if (type_ == ModuleType::EXEC || type_ == ModuleType::SO)
    bcc_elf_foreach_sym(name_.c_str(), _add_symbol, symbol_option_, this);
  if (type_ == ModuleType::VDSO)
    bcc_elf_foreach_vdso_sym(_add_symbol, this);

  std::sort(syms_.begin(), syms_.end());
}

bool ProcSyms::Module::contains(uint64_t addr, uint64_t &offset) const {
  for (const auto &range : ranges_) {
    if (addr >= range.start && addr < range.end) {
      if (type_ == ModuleType::SO || type_ == ModuleType::VDSO) {
        // Offset within the mmap
        offset = addr - range.start + range.file_offset;

        // Offset within the ELF for SO symbol lookup
        offset += (elf_so_addr_ - elf_so_offset_);
      } else {
        offset = addr;
      }

      return true;
    }
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
  uint64_t file_offset;
};

static int _find_module(const char *modname, uint64_t start, uint64_t end,
                        uint64_t offset, bool, void *p) {
  struct mod_st *mod = (struct mod_st *)p;
  if (!strcmp(modname, mod->name)) {
    mod->start = start;
    mod->file_offset = offset;
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

  *global = mod.start - mod.file_offset + address;
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

struct load_addr_t {
  uint64_t target_addr;
  uint64_t binary_addr;
};
int _find_load(uint64_t v_addr, uint64_t mem_sz, uint64_t file_offset,
                       void *payload) {
  struct load_addr_t *addr = static_cast<load_addr_t *>(payload);
  if (addr->target_addr >= v_addr && addr->target_addr < (v_addr + mem_sz)) {
    addr->binary_addr = addr->target_addr - v_addr + file_offset;
    return -1;
  }
  return 0;
}

int bcc_resolve_symname(const char *module, const char *symname,
                        const uint64_t addr, int pid,
                        struct bcc_symbol_option *option,
                        struct bcc_symbol *sym) {
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

  sym->name = symname;
  sym->offset = addr;
  if (option == NULL)
    option = &default_option;

  if (sym->name && sym->offset == 0x0)
    if (bcc_elf_foreach_sym(sym->module, _find_sym, option, sym) < 0)
      goto invalid_module;
  if (sym->offset == 0x0)
    goto invalid_module;

  // For executable (ET_EXEC) binaries, translate the virtual address
  // to physical address in the binary file.
  // For shared object binaries (ET_DYN), the address from symbol table should
  // already be physical address in the binary file.
  if (bcc_elf_get_type(sym->module) == ET_EXEC) {
    struct load_addr_t addr = {
      .target_addr = sym->offset,
      .binary_addr = 0x0,
    };
    if (bcc_elf_foreach_load_section(sym->module, &_find_load, &addr) < 0)
      goto invalid_module;
    if (!addr.binary_addr)
      goto invalid_module;
    sym->offset = addr.binary_addr;
  }
  return 0;

invalid_module:
  if (sym->module) {
    ::free(const_cast<char*>(sym->module));
    sym->module = NULL;
  }
  return -1;
}
}
