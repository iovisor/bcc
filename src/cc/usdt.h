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

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "syms.h"
#include "vendor/optional.hpp"

struct bcc_usdt;

namespace USDT {

using std::experimental::optional;
using std::experimental::nullopt;
class ArgumentParser;

static const std::string USDT_PROGRAM_HEADER =
    "#include <uapi/linux/ptrace.h>\n";

class Argument {
private:
  optional<int> arg_size_;
  optional<int> constant_;
  optional<int> deref_offset_;
  optional<std::string> deref_ident_;
  optional<std::string> base_register_name_;
  optional<std::string> index_register_name_;
  optional<int> scale_;

  bool get_global_address(uint64_t *address, const std::string &binpath,
                          const optional<int> &pid) const;

public:
  Argument();
  ~Argument();

  bool assign_to_local(std::ostream &stream, const std::string &local_name,
                       const std::string &binpath,
                       const optional<int> &pid = nullopt) const;

  int arg_size() const { return arg_size_.value_or(sizeof(void *)); }
  std::string ctype() const;

  const optional<std::string> &deref_ident() const { return deref_ident_; }
  const optional<std::string> &base_register_name() const {
    return base_register_name_;
  }
  const optional<std::string> &index_register_name() const {
    return index_register_name_;
  }
  const optional<int> scale() const { return scale_; }
  const optional<int> constant() const { return constant_; }
  const optional<int> deref_offset() const { return deref_offset_; }

  friend class ArgumentParser;
};

class ArgumentParser {
  const char *arg_;
  ssize_t cur_pos_;

  void skip_whitespace_from(size_t pos);
  void skip_until_whitespace_from(size_t pos);

protected:
  virtual bool normalize_register(std::string *reg, int *reg_size) = 0;

  ssize_t parse_register(ssize_t pos, std::string &name, int &size);
  ssize_t parse_number(ssize_t pos, optional<int> *number);
  ssize_t parse_identifier(ssize_t pos, optional<std::string> *ident);
  ssize_t parse_base_register(ssize_t pos, Argument *dest);
  ssize_t parse_index_register(ssize_t pos, Argument *dest);
  ssize_t parse_scale(ssize_t pos, Argument *dest);
  ssize_t parse_expr(ssize_t pos, Argument *dest);
  ssize_t parse_1(ssize_t pos, Argument *dest);

  void print_error(ssize_t pos);

public:
  bool parse(Argument *dest);
  bool done() { return cur_pos_ < 0 || arg_[cur_pos_] == '\0'; }

  ArgumentParser(const char *arg) : arg_(arg), cur_pos_(0) {}
};

class ArgumentParser_x64 : public ArgumentParser {
  enum Register {
    REG_A,
    REG_B,
    REG_C,
    REG_D,
    REG_SI,
    REG_DI,
    REG_BP,
    REG_SP,
    REG_8,
    REG_9,
    REG_10,
    REG_11,
    REG_12,
    REG_13,
    REG_14,
    REG_15,
    REG_RIP,
  };

  struct RegInfo {
    Register reg;
    int size;
  };

  static const std::unordered_map<std::string, RegInfo> registers_;
  bool normalize_register(std::string *reg, int *reg_size);
  void reg_to_name(std::string *norm, Register reg);

public:
  ArgumentParser_x64(const char *arg) : ArgumentParser(arg) {}
};

struct Location {
  uint64_t address_;
  std::vector<Argument> arguments_;
  Location(uint64_t addr, const char *arg_fmt);
};

class Probe {
  std::string bin_path_;
  std::string provider_;
  std::string name_;
  uint64_t semaphore_;

  std::vector<Location> locations_;

  optional<int> pid_;
  optional<bool> in_shared_object_;

  optional<std::string> attached_to_;
  optional<uint64_t> attached_semaphore_;

  std::string largest_arg_type(size_t arg_n);

  bool add_to_semaphore(int16_t val);
  bool resolve_global_address(uint64_t *global, const uint64_t addr);
  bool lookup_semaphore_addr(uint64_t *address);
  void add_location(uint64_t addr, const char *fmt);

public:
  Probe(const char *bin_path, const char *provider, const char *name,
        uint64_t semaphore, const optional<int> &pid);

  size_t num_locations() const { return locations_.size(); }
  size_t num_arguments() const { return locations_.front().arguments_.size(); }
  uint64_t semaphore()   const { return semaphore_; }

  uint64_t address(size_t n = 0) const { return locations_[n].address_; }
  const Location &location(size_t n) const { return locations_[n]; }
  bool usdt_getarg(std::ostream &stream);
  std::string get_arg_ctype(int arg_index) {
    return largest_arg_type(arg_index);
  }

  bool need_enable() const { return semaphore_ != 0x0; }
  bool enable(const std::string &fn_name);
  bool disable();
  bool enabled() const { return !!attached_to_; }

  bool in_shared_object();
  const std::string &name() { return name_; }
  const std::string &bin_path() { return bin_path_; }
  const std::string &provider() { return provider_; }

  friend class Context;
};

class Context {
  std::vector<std::unique_ptr<Probe>> probes_;
  std::unordered_set<std::string> modules_;

  optional<int> pid_;
  optional<ProcStat> pid_stat_;
  bool loaded_;

  static void _each_probe(const char *binpath, const struct bcc_elf_usdt *probe,
                          void *p);
  static int _each_module(const char *modpath, uint64_t, uint64_t, void *p);

  void add_probe(const char *binpath, const struct bcc_elf_usdt *probe);
  std::string resolve_bin_path(const std::string &bin_path);

public:
  Context(const std::string &bin_path);
  Context(int pid);
  ~Context();

  optional<int> pid() const { return pid_; }
  bool loaded() const { return loaded_; }
  size_t num_probes() const { return probes_.size(); }

  Probe *get(const std::string &probe_name);
  Probe *get(int pos) { return probes_[pos].get(); }

  bool enable_probe(const std::string &probe_name, const std::string &fn_name);
  bool generate_usdt_args(std::ostream &stream);

  typedef void (*each_cb)(struct bcc_usdt *);
  void each(each_cb callback);

  typedef void (*each_uprobe_cb)(const char *, const char *, uint64_t, int);
  void each_uprobe(each_uprobe_cb callback);
};
}
