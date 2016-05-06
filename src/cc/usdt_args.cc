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
#include <unordered_map>

#include "syms.h"
#include "usdt.h"
#include "vendor/tinyformat.hpp"

#include "bcc_elf.h"
#include "bcc_syms.h"

namespace USDT {

Argument::Argument() {}
Argument::~Argument() {}

std::string Argument::ctype() const {
  const int s = arg_size() * 8;
  return (s < 0) ? tfm::format("int%d_t", -s) : tfm::format("uint%d_t", s);
}

bool Argument::get_global_address(uint64_t *address, const std::string &binpath,
                                  const optional<int> &pid) const {
  if (pid) {
    return ProcSyms(*pid)
        .resolve_name(binpath.c_str(), deref_ident_->c_str(), address);
  }

  if (bcc_elf_is_shared_obj(binpath.c_str()) == 0) {
    struct bcc_symbol sym = {deref_ident_->c_str(), binpath.c_str(), 0x0};
    if (!bcc_find_symbol_addr(&sym) && sym.offset) {
      *address = sym.offset;
      return true;
    }
  }

  return false;
}

bool Argument::assign_to_local(std::ostream &stream,
                               const std::string &local_name,
                               const std::string &binpath,
                               const optional<int> &pid) const {
  if (constant_) {
    tfm::format(stream, "%s = %d;", local_name, *constant_);
    return true;
  }

  if (!deref_offset_) {
    tfm::format(stream, "%s = (%s)ctx->%s;", local_name, ctype(),
                *register_name_);
    return true;
  }

  if (deref_offset_ && !deref_ident_) {
    tfm::format(stream,
                "{ u64 __addr = ctx->%s + (%d); %s __res = 0x0; "
                "bpf_probe_read(&__res, sizeof(__res), (void *)__addr); "
                "%s = __res; }",
                *register_name_, *deref_offset_, ctype(), local_name);
    return true;
  }

  if (deref_offset_ && deref_ident_ && *register_name_ == "ip") {
    uint64_t global_address;
    if (!get_global_address(&global_address, binpath, pid))
      return false;

    tfm::format(stream,
                "{ u64 __addr = 0x%xull + %d; %s __res = 0x0; "
                "bpf_probe_read(&__res, sizeof(__res), (void *)__addr); "
                "%s = __res; }",
                global_address, *deref_offset_, ctype(), local_name);
    return true;
  }

  return false;
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
  ssize_t start = ++pos;
  if (arg_[start - 1] != '%')
    return -start;

  while (isalnum(arg_[pos])) pos++;

  std::string regname(arg_ + start, pos - start);
  int regsize = 0;

  if (!normalize_register(&regname, &regsize))
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

const std::unordered_map<std::string, ArgumentParser_x64::RegInfo>
    ArgumentParser_x64::registers_ = {
        {"rax", {REG_A, 8}},   {"eax", {REG_A, 4}},
        {"ax", {REG_A, 2}},    {"al", {REG_A, 1}},

        {"rbx", {REG_B, 8}},   {"ebx", {REG_B, 4}},
        {"bx", {REG_B, 2}},    {"bl", {REG_B, 1}},

        {"rcx", {REG_C, 8}},   {"ecx", {REG_C, 4}},
        {"cx", {REG_C, 2}},    {"cl", {REG_C, 1}},

        {"rdx", {REG_D, 8}},   {"edx", {REG_D, 4}},
        {"dx", {REG_D, 2}},    {"dl", {REG_D, 1}},

        {"rsi", {REG_SI, 8}},  {"esi", {REG_SI, 4}},
        {"si", {REG_SI, 2}},   {"sil", {REG_SI, 1}},

        {"rdi", {REG_DI, 8}},  {"edi", {REG_DI, 4}},
        {"di", {REG_DI, 2}},   {"dil", {REG_DI, 1}},

        {"rbp", {REG_BP, 8}},  {"ebp", {REG_BP, 4}},
        {"bp", {REG_BP, 2}},   {"bpl", {REG_BP, 1}},

        {"rsp", {REG_SP, 8}},  {"esp", {REG_SP, 4}},
        {"sp", {REG_SP, 2}},   {"spl", {REG_SP, 1}},

        {"r8", {REG_8, 8}},    {"r8d", {REG_8, 4}},
        {"r8w", {REG_8, 2}},   {"r8b", {REG_8, 1}},

        {"r9", {REG_9, 8}},    {"r9d", {REG_9, 4}},
        {"r9w", {REG_9, 2}},   {"r9b", {REG_9, 1}},

        {"r10", {REG_10, 8}},  {"r10d", {REG_10, 4}},
        {"r10w", {REG_10, 2}}, {"r10b", {REG_10, 1}},

        {"r11", {REG_11, 8}},  {"r11d", {REG_11, 4}},
        {"r11w", {REG_11, 2}}, {"r11b", {REG_11, 1}},

        {"r12", {REG_12, 8}},  {"r12d", {REG_12, 4}},
        {"r12w", {REG_12, 2}}, {"r12b", {REG_12, 1}},

        {"r13", {REG_13, 8}},  {"r13d", {REG_13, 4}},
        {"r13w", {REG_13, 2}}, {"r13b", {REG_13, 1}},

        {"r14", {REG_14, 8}},  {"r14d", {REG_14, 4}},
        {"r14w", {REG_14, 2}}, {"r14b", {REG_14, 1}},

        {"r15", {REG_15, 8}},  {"r15d", {REG_15, 4}},
        {"r15w", {REG_15, 2}}, {"r15b", {REG_15, 1}},

        {"rip", {REG_RIP, 8}},
};

void ArgumentParser_x64::reg_to_name(std::string *norm, Register reg) {
  switch (reg) {
  case REG_A:
    *norm = "ax";
    break;
  case REG_B:
    *norm = "bx";
    break;
  case REG_C:
    *norm = "cx";
    break;
  case REG_D:
    *norm = "dx";
    break;

  case REG_SI:
    *norm = "si";
    break;
  case REG_DI:
    *norm = "di";
    break;
  case REG_BP:
    *norm = "bp";
    break;
  case REG_SP:
    *norm = "sp";
    break;

  case REG_8:
    *norm = "r8";
    break;
  case REG_9:
    *norm = "r9";
    break;
  case REG_10:
    *norm = "r10";
    break;
  case REG_11:
    *norm = "r11";
    break;
  case REG_12:
    *norm = "r12";
    break;
  case REG_13:
    *norm = "r13";
    break;
  case REG_14:
    *norm = "r14";
    break;
  case REG_15:
    *norm = "r15";
    break;

  case REG_RIP:
    *norm = "ip";
    break;
  }
}

bool ArgumentParser_x64::normalize_register(std::string *reg, int *reg_size) {
  auto it = registers_.find(*reg);
  if (it == registers_.end())
    return false;

  *reg_size = it->second.size;
  reg_to_name(reg, it->second.reg);
  return true;
}
}
