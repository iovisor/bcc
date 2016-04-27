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

 public:
  Argument();
  ~Argument();

  int arg_size() const { return arg_size_.value_or(sizeof(void *)); }

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

struct Probe {
  std::string _bin_path;
  std::string _provider;
  std::string _name;
  uint64_t _semaphore;

  Probe(const char *bin_path, const char *provider, const char *name,
        uint64_t semaphore)
      : _bin_path(bin_path),
        _provider(provider),
        _name(name),
        _semaphore(semaphore) {}
};
}
