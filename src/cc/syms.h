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
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/types.h>

class ProcStat {
  std::string procfs_;
  ino_t inode_;
  ino_t getinode_();

public:
  ProcStat(int pid);
  bool is_stale() { return inode_ != getinode_(); }
  void reset() { inode_ = getinode_(); }
};

class SymbolCache {
public:
  virtual ~SymbolCache() = default;

  virtual void refresh() = 0;
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym) = 0;
  virtual bool resolve_name(const char *module, const char *name,
                            uint64_t *addr) = 0;
};

class KSyms : SymbolCache {
  struct Symbol {
    Symbol(const char *name, uint64_t addr) : name(name), addr(addr) {}
    std::string name;
    uint64_t addr;

    bool operator<(const Symbol &rhs) const { return addr < rhs.addr; }
  };

  std::vector<Symbol> syms_;
  std::unordered_map<std::string, uint64_t> symnames_;
  static void _add_symbol(const char *, uint64_t, void *);

public:
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym);
  virtual bool resolve_name(const char *unused, const char *name,
                            uint64_t *addr);
  virtual void refresh();
};

class ProcSyms : SymbolCache {
  struct Symbol {
    Symbol(const std::string *name, uint64_t start, uint64_t size, int flags = 0)
        : name(name), start(start), size(size), flags(flags) {}
    const std::string *name;
    uint64_t start;
    uint64_t size;
    int flags;

    bool operator<(const struct Symbol& rhs) const {
      return start < rhs.start;
    }
  };

  struct Module {
    Module(const char *name, uint64_t start, uint64_t end)
        : name_(name), start_(start), end_(end) {}
    std::string name_;
    uint64_t start_;
    uint64_t end_;
    std::unordered_set<std::string> symnames_;
    std::vector<Symbol> syms_;

    void load_sym_table();
    bool find_addr(uint64_t addr, struct bcc_symbol *sym);
    bool find_name(const char *symname, uint64_t *addr);
    bool is_so() const;
    bool is_perf_map() const;

    static int _add_symbol(const char *symname, uint64_t start, uint64_t end,
                           int flags, void *p);
  };

  int pid_;
  std::vector<Module> modules_;
  ProcStat procstat_;

  static int _add_module(const char *, uint64_t, uint64_t, void *);
  bool load_modules();

public:
  ProcSyms(int pid);
  virtual void refresh();
  virtual bool resolve_addr(uint64_t addr, struct bcc_symbol *sym);
  virtual bool resolve_name(const char *module, const char *name,
                            uint64_t *addr);
};
