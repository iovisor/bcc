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
#pragma once

#include <algorithm>
#include <memory>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "bcc_proc.h"
#include "bcc_syms.h"
#include "file_desc.h"

class ProcStat {
  std::string procfs_;
  ino_t inode_;
  ino_t getinode_();

public:
  ProcStat(int pid);
  bool is_stale();
  void reset() { inode_ = getinode_(); }
};

class SymbolCache {
public:
  virtual ~SymbolCache() = default;

  virtual void refresh() = 0;
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym, bool demangle = true) = 0;
  virtual bool resolve_name(const char *module, const char *name,
                            uint64_t *addr) = 0;
};

class KSyms : SymbolCache {
  struct Symbol {
    Symbol(const char *name, const char *mod, uint64_t addr) : name(name), mod(mod), addr(addr) {}
    std::string name;
    std::string mod;
    uint64_t addr;

    bool operator<(const Symbol &rhs) const { return addr < rhs.addr; }
  };

  std::vector<Symbol> syms_;
  std::unordered_map<std::string, uint64_t> symnames_;
  static void _add_symbol(const char *, const char *, uint64_t, void *);

public:
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym, bool demangle = true) override;
  virtual bool resolve_name(const char *unused, const char *name,
                            uint64_t *addr) override;
  virtual void refresh() override;
};

class ProcSyms : SymbolCache {
  struct NameIdx {
    size_t section_idx;
    size_t str_table_idx;
    size_t str_len;
    bool debugfile;
  };

  struct Symbol {
    Symbol(const std::string *name, uint64_t start, uint64_t size)
        : is_name_resolved(true), start(start), size(size) {
      data.name = name;
    }
    Symbol(size_t section_idx, size_t str_table_idx, size_t str_len, uint64_t start,
           uint64_t size, bool debugfile)
        : is_name_resolved(false), start(start), size(size) {
      data.name_idx.section_idx = section_idx;
      data.name_idx.str_table_idx = str_table_idx;
      data.name_idx.str_len = str_len;
      data.name_idx.debugfile = debugfile;
    }
    bool is_name_resolved;
    union {
      struct NameIdx name_idx;
      const std::string *name{nullptr};
    } data;
    uint64_t start;
    uint64_t size;

    bool operator<(const struct Symbol& rhs) const {
      return start < rhs.start;
    }
  };

  enum class ModuleType {
    UNKNOWN,
    EXEC,
    SO,
    PERF_MAP,
    VDSO
  };

  struct Module {
    struct Range {
      uint64_t start;
      uint64_t end;
      uint64_t file_offset;
      Range(uint64_t s, uint64_t e, uint64_t f)
          : start(s), end(e), file_offset(f) {}
    };

    Module(const char *name, const char *path, struct bcc_symbol_option *option);

    std::string name_;
    std::string path_;
    std::vector<Range> ranges_;
    bool loaded_;
    bcc_symbol_option *symbol_option_;
    ModuleType type_;

    // The file offset within the ELF of the SO's first text section.
    uint64_t elf_so_offset_;
    uint64_t elf_so_addr_;

    std::unordered_set<std::string> symnames_;
    std::vector<Symbol> syms_;

    void load_sym_table();

    bool contains(uint64_t addr, uint64_t &offset) const;
    uint64_t start() const { return ranges_.begin()->start; }

    bool find_addr(uint64_t offset, struct bcc_symbol *sym);
    bool find_name(const char *symname, uint64_t *addr);

    static int _add_symbol(const char *symname, uint64_t start, uint64_t size,
                           void *p);
    static int _add_symbol_lazy(size_t section_idx, size_t str_table_idx,
                                size_t str_len, uint64_t start, uint64_t size,
                                int debugfile, void *p);
  };

  int pid_;
  std::vector<Module> modules_;
  ProcStat procstat_;
  bcc_symbol_option symbol_option_;

  static int _add_load_sections(uint64_t v_addr, uint64_t mem_sz,
                                uint64_t file_offset, void *payload);
  static int _add_module(mod_info *, int, void *);
  void load_exe();
  void load_modules();

public:
  ProcSyms(int pid, struct bcc_symbol_option *option = nullptr);
  virtual void refresh() override;
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym, bool demangle = true) override;
  virtual bool resolve_name(const char *module, const char *name,
                            uint64_t *addr) override;
};

class BuildSyms {
  struct Symbol {
    Symbol(const std::string *name, uint64_t start, uint64_t size)
      :name(name), start(start), size(size) {}
    const std::string *name;
    uint64_t start;
    uint64_t size;

    bool operator<(const struct Symbol &rhs) const {
      return start < rhs.start;
    }
  };

  struct Module {
    Module(const char *module_name):
      module_name_(module_name),
      loaded_(false) {}
    const std::string module_name_;
    const std::string build_id_;
    bool loaded_;
    std::unordered_set<std::string> symnames_;
    std::vector<Symbol> syms_;
    bcc_symbol_option symbol_option_;

    bool load_sym_table();
    static int _add_symbol(const char *symname, uint64_t start, uint64_t size,
                            void *p);
    bool resolve_addr(uint64_t offset, struct bcc_symbol*, bool demangle=true);
  };

  std::unordered_map<std::string, std::unique_ptr<Module> > buildmap_;

public:
  BuildSyms() {}
  virtual ~BuildSyms() = default;
  virtual bool add_module(const std::string module_name);
  virtual bool resolve_addr(std::string build_id, uint64_t offset, struct bcc_symbol *sym, bool demangle = true);
};
