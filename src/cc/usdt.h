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

#include <string>
#include <unordered_map>
#include <vector>

#include "vendor/optional.hpp"

namespace USDT {

using std::experimental::optional;
using std::experimental::nullopt;
class ArgumentParser;

class Argument {
private:
  optional<int> arg_size_;
  optional<int> constant_;
  optional<int> deref_offset_;
  optional<std::string> deref_ident_;
  optional<std::string> register_name_;

  uint64_t get_global_address(const std::string &binpath,
                              const optional<int> &pid) const;
  static const std::unordered_map<std::string, std::string> translations_;

public:
  Argument();
  ~Argument();

  void assign_to_local(std::ostream &stream, const std::string &local_name,
                       const std::string &binpath,
                       const optional<int> &pid = nullopt) const;

  int arg_size() const { return arg_size_.value_or(sizeof(void *)); }
  std::string ctype() const;
  void normalize_register_name(std::string *normalized) const;

  const optional<std::string> &deref_ident() const { return deref_ident_; }
  const optional<std::string> &register_name() const { return register_name_; }
  const optional<int> constant() const { return constant_; }
  const optional<int> deref_offset() const { return deref_offset_; }

  friend class ArgumentParser;
};

class ArgumentParser {
  const char *arg_;
  ssize_t cur_pos_;

protected:
  virtual bool validate_register(const std::string &reg, int *reg_size) = 0;

  ssize_t parse_number(ssize_t pos, optional<int> *number);
  ssize_t parse_identifier(ssize_t pos, optional<std::string> *ident);
  ssize_t parse_register(ssize_t pos, Argument *dest);
  ssize_t parse_expr(ssize_t pos, Argument *dest);
  ssize_t parse_1(ssize_t pos, Argument *dest);

  void print_error(ssize_t pos);

public:
  bool parse(Argument *dest);
  bool done() { return arg_[cur_pos_] == '\0'; }

  ArgumentParser(const char *arg) : arg_(arg), cur_pos_(0) {}
};

class ArgumentParser_x64 : public ArgumentParser {
  static const std::unordered_map<std::string, int> registers_;
  bool validate_register(const std::string &reg, int *reg_size);

public:
  ArgumentParser_x64(const char *arg) : ArgumentParser(arg) {}
};

class Probe {
  std::string bin_path_;
  std::string provider_;
  std::string name_;
  uint64_t semaphore_;

  struct Location {
    uint64_t address_;
    std::vector<Argument *> arguments_;
    Location(uint64_t addr, const char *arg_fmt);
  };

  std::vector<Location> locations_;

  std::string gen_thunks_;
  std::string gen_cases_;

public:
  Probe(const char *bin_path, const char *provider, const char *name,
        uint64_t semaphore);

  void add_location(uint64_t addr, const char *fmt);
  bool need_enable() const { return semaphore_ != 0x0; }
  size_t location_count() const { return locations_.size(); }

  const std::string &usdt_thunks(const std::string &prefix);
  const std::string &usdt_cases(const optional<int> &pid);

  friend class Context;
};

class Context {
  std::vector<Probe *> probes_;

  static void _each_probe(const char *binpath, const struct bcc_elf_usdt *probe,
                          void *p);
  void add_probe(const char *binpath, const struct bcc_elf_usdt *probe);
  void add_probes(const std::string &bin_path);

public:
  Context(const std::string &bin_path);
  Context(int pid);
};
}
