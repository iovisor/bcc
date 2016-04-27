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
#include "usdt.h"
#include <unordered_map>
#include "vendor/tinyformat.hpp"

namespace USDT {

Argument::Argument() {}
Argument::~Argument() {}

const std::unordered_map<std::string, std::string> Argument::translations_ = {
  {"rax", "ax"}, {"rbx", "bx"}, {"rcx", "cx"}, {"rdx", "dx"},
  {"rdi", "di"}, {"rsi", "si"}, {"rbp", "bp"}, {"rsp", "sp"},
  {"rip", "ip"}, {"eax", "ax"}, {"ebx", "bx"}, {"ecx", "cx"},
  {"edx", "dx"}, {"edi", "di"}, {"esi", "si"}, {"ebp", "bp"},
  {"esp", "sp"}, {"eip", "ip"},

  {"al", "ax"}, {"bl", "bx"}, {"cl", "cx"}, {"dl", "dx"}
};

std::string Argument::ctype() const {
  const int s = arg_size() * 8;
  return (s < 0) ?
    tfm::format("int%d_t", -s) :
    tfm::format("uint%d_t", s);
}

void Argument::normalize_register_name(std::string *normalized) const {
  if (!register_name_)
    return;

  normalized->assign(*register_name_);
  if ((*normalized)[0] == '%')
    normalized->erase(0, 1);

  auto it = translations_.find(*normalized);
  if (it != translations_.end())
    normalized->assign(it->second);
}

uint64_t Argument::get_global_address(int pid) const {
  return 0x0;
}

void Argument::assign_to_local(std::ostream &stream,
    const std::string &local_name, optional<int> pid) const {

  std::string regname;
  normalize_register_name(&regname);

  if (constant_) {
    tfm::format(stream, "%s = %d;", local_name, *constant_);
    return;
  }

  if (!deref_offset_) {
    tfm::format(stream, "%s = (%s)ctx->%s;", local_name, ctype(), regname);
    return;
  }

  if (deref_offset_ && !deref_ident_) {
    tfm::format(stream,
      "{\n"
      "    u64 __temp = ctx->%s + (%d);\n"
      "    bpf_probe_read(&%s, sizeof(%s), (void *)__temp);\n"
      "}\n",
      regname, *deref_offset_, local_name, local_name);
    return;
  }

  tfm::format(stream,
    "{\n"
    "    u64 __temp = 0x%xull + %d;\n"
    "    bpf_probe_read(&%s, sizeof(%s), (void *)__temp);\n"
    "}\n",
    get_global_address(pid.value_or(-1)),
    *deref_offset_, local_name, local_name);
}

ssize_t ArgumentParser::parse_number(ssize_t pos, optional<int> *result) {
  char *endp;
  int number = strtol(arg_ + pos, &endp, 0);
  if (endp > arg_ + pos)
    *result = number;
  return endp - arg_;
}

ssize_t ArgumentParser::parse_identifier(ssize_t pos,
                                         optional<std::string> *result) {
  if (isalpha(arg_[pos]) || arg_[pos] == '_') {
    ssize_t start = pos++;
    while (isalnum(arg_[pos]) || arg_[pos] == '_') pos++;
    if (pos - start)
      result->emplace(arg_ + start, pos - start);
  }
  return pos;
}

ssize_t ArgumentParser::parse_register(ssize_t pos, Argument *dest) {
  ssize_t start = pos++;
  if (arg_[start] != '%')
    return -start;
  while (isalnum(arg_[pos])) pos++;

  std::string regname(arg_ + start, pos - start);
  int regsize = 0;

  if (!validate_register(regname, &regsize))
    return -start;

  dest->register_name_ = regname;
  if (!dest->arg_size_)
    dest->arg_size_ = regsize;

  return pos;
}

ssize_t ArgumentParser::parse_expr(ssize_t pos, Argument *dest) {
  if (arg_[pos] == '$')
    return parse_number(pos + 1, &dest->constant_);

  if (arg_[pos] == '%')
    return parse_register(pos, dest);

  if (isdigit(arg_[pos]) || arg_[pos] == '-') {
    pos = parse_number(pos, &dest->deref_offset_);
    if (arg_[pos] == '+') {
      pos = parse_identifier(pos + 1, &dest->deref_ident_);
      if (!dest->deref_ident_)
        return -pos;
    }
  } else {
    dest->deref_offset_ = 0;
    pos = parse_identifier(pos, &dest->deref_ident_);
  }

  if (arg_[pos] != '(')
    return -pos;

  pos = parse_register(pos + 1, dest);
  if (pos < 0)
    return pos;

  return (arg_[pos] == ')') ? pos + 1 : -pos;
}

ssize_t ArgumentParser::parse_1(ssize_t pos, Argument *dest) {
  if (isdigit(arg_[pos]) || arg_[pos] == '-') {
    optional<int> asize;
    ssize_t m = parse_number(pos, &asize);
    if (arg_[m] == '@' && asize) {
      dest->arg_size_ = asize;
      return parse_expr(m + 1, dest);
    }
  }
  return parse_expr(pos, dest);
}

void ArgumentParser::print_error(ssize_t pos) {
  fprintf(stderr, "Parse error:\n    %s\n", arg_);
  for (ssize_t i = 0; i < pos + 4; ++i) fputc('-', stderr);
  fputc('^', stderr);
  fputc('\n', stderr);
}

bool ArgumentParser::parse(Argument *dest) {
  if (done())
    return false;

  ssize_t res = parse_1(cur_pos_, dest);
  if (res < 0) {
    print_error(-res);
    return false;
  }
  if (!isspace(arg_[res]) && arg_[res] != '\0') {
    print_error(res);
    return false;
  }
  while (isspace(arg_[res])) res++;
  cur_pos_ = res;
  return true;
}

const std::unordered_map<std::string, int> ArgumentParser_x64::registers_ = {
    {"%rax", 8}, {"%rbx", 8}, {"%rcx", 8}, {"%rdx", 8}, {"%rdi", 8},
    {"%rsi", 8}, {"%rbp", 8}, {"%rsp", 8}, {"%rip", 8}, {"%r8", 8},
    {"%r9", 8},  {"%r10", 8}, {"%r11", 8}, {"%r12", 8}, {"%r13", 8},
    {"%r14", 8}, {"%r15", 8},

    {"%eax", 4}, {"%ebx", 4}, {"%ecx", 4}, {"%edx", 4}, {"%edi", 4},
    {"%esi", 4}, {"%ebp", 4}, {"%esp", 4}, {"%eip", 4},

    {"%ax", 2},  {"%bx", 2},  {"%cx", 2},  {"%dx", 2},  {"%di", 2},
    {"%si", 2},  {"%bp", 2},  {"%sp", 2},  {"%ip", 2},

    {"%al", 1},  {"%bl", 1},  {"%cl", 1},  {"%dl", 1}};

bool ArgumentParser_x64::validate_register(const std::string &reg,
                                           int *reg_size) {
  auto it = registers_.find(reg);
  if (it == registers_.end())
    return false;
  *reg_size = it->second;
  return true;
}
}
