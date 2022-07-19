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
#include <cmath>
#include <unordered_map>
#include <regex>

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

static const char *type_names[][4] = {
  { "int8_t", "int16_t", "int32_t", "int64_t" },
  { "uint8_t", "uint16_t", "uint32_t", "uint64_t" },
};

const char *Argument::ctype_name() const {
  const int s = arg_size();
  const int r = log2(abs(s));
  return s < 0 ? type_names[0][r] : type_names[1][r];
}

bool Argument::get_global_address(uint64_t *address, const std::string &binpath,
                                  const optional<int> &pid) const {
  if (pid) {
    static struct bcc_symbol_option default_option = {
      .use_debug_file = 1,
      .check_debug_file_crc = 1,
      .lazy_symbolize = 1,
      .use_symbol_type = BCC_SYM_ALL_TYPES
    };
    return ProcSyms(*pid, &default_option)
        .resolve_name(binpath.c_str(), deref_ident_->c_str(), address);
  }

  if (!bcc_elf_is_shared_obj(binpath.c_str())) {
    struct bcc_symbol sym;
    if (bcc_resolve_symname(binpath.c_str(), deref_ident_->c_str(), 0x0, -1, nullptr, &sym) == 0) {
      *address = sym.offset;
      if (sym.module)
        ::free(const_cast<char*>(sym.module));
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
    tfm::format(stream, "%s = %lld;", local_name, *constant_);
    return true;
  }

  if (!deref_offset_) {
    if(base_register_name_->substr(0,3) == "xmm") {
      // TODO: When we can read xmm registers from BPF, update this to read
      // the actual value
      tfm::format(stream, "%s = 0;", local_name);
    } else {
      tfm::format(stream, "%s = ctx->%s;", local_name, *base_register_name_);
    }
    // Put a compiler barrier to prevent optimization
    // like llvm SimplifyCFG SinkThenElseCodeToEnd
    // Volatile marking is not sufficient to prevent such optimization.
    tfm::format(stream, " %s", COMPILER_BARRIER);
    return true;
  }

  if (deref_offset_ && !deref_ident_) {
    tfm::format(stream, "{ u64 __addr = ctx->%s + %d",
                *base_register_name_, *deref_offset_);
    if (index_register_name_) {
      int scale = scale_.value_or(1);
      tfm::format(stream, " + (ctx->%s * %d);", *index_register_name_, scale);
    } else {
      tfm::format(stream, ";");
    }
    // Theoretically, llvm SimplifyCFG SinkThenElseCodeToEnd may still
    // sink bpf_probe_read call, so put a barrier here to prevent sinking
    // of ctx->#fields.
    tfm::format(stream, " %s ", COMPILER_BARRIER);
    tfm::format(stream,
                "%s __res = 0x0; "
                "bpf_probe_read_user(&__res, sizeof(__res), (void *)__addr); "
                "%s = __res; }",
                ctype(), local_name);
    return true;
  }

  if (deref_offset_ && deref_ident_ && *base_register_name_ == "ip") {
    uint64_t global_address;
    if (!get_global_address(&global_address, binpath, pid))
      return false;

    tfm::format(stream,
                "{ u64 __addr = 0x%xull + %d; %s __res = 0x0; "
                "bpf_probe_read_user(&__res, sizeof(__res), (void *)__addr); "
                "%s = __res; }",
                global_address, *deref_offset_, ctype(), local_name);
    return true;
  }

  return false;
}

void ArgumentParser::print_error(ssize_t pos) {
  fprintf(stderr, "Parse error:\n    %s\n", arg_);
  for (ssize_t i = 0; i < pos + 4; ++i) fputc('-', stderr);
  fputc('^', stderr);
  fputc('\n', stderr);
}

void ArgumentParser::skip_whitespace_from(size_t pos) {
    while (isspace(arg_[pos])) pos++;
    cur_pos_ = pos;
}

void ArgumentParser::skip_until_whitespace_from(size_t pos) {
    while (arg_[pos] != '\0' && !isspace(arg_[pos]))
        pos++;
    cur_pos_ = pos;
}

bool ArgumentParser_aarch64::parse_register(ssize_t pos, ssize_t &new_pos,
                                            std::string &reg_name) {
  if (arg_[pos] == 'x') {
    optional<int> reg_num;
    new_pos = parse_number(pos + 1, &reg_num);
    if (new_pos == pos + 1 || *reg_num < 0 || *reg_num > 31)
      return error_return(pos + 1, pos + 1);

    if (*reg_num == 31) {
      reg_name = "sp";
    } else {
      reg_name = "regs[" + std::to_string(reg_num.value()) + "]";
    }

    return true;
  } else if (arg_[pos] == 's' && arg_[pos + 1] == 'p') {
    reg_name = "sp";
    new_pos = pos + 2;
    return true;
  } else {
    return error_return(pos, pos);
  }
}

bool ArgumentParser_aarch64::parse_size(ssize_t pos, ssize_t &new_pos,
                                        optional<int> *arg_size) {
  int abs_arg_size;

  new_pos = parse_number(pos, arg_size);
  if (new_pos == pos)
    return error_return(pos, pos);

  abs_arg_size = abs(arg_size->value());
  if (abs_arg_size != 1 && abs_arg_size != 2 && abs_arg_size != 4 &&
      abs_arg_size != 8)
    return error_return(pos, pos);
  return true;
}

bool ArgumentParser_aarch64::parse_mem(ssize_t pos, ssize_t &new_pos,
                                       Argument *dest) {
  std::string base_reg_name, index_reg_name;

  if (parse_register(pos, new_pos, base_reg_name) == false)
    return false;
  dest->base_register_name_ = base_reg_name;

  if (arg_[new_pos] == ',') {
    pos = new_pos + 1;
    new_pos = parse_number(pos, &dest->deref_offset_);
    if (new_pos == pos) {
      // offset isn't a number, so it should be a reg,
      // which looks like: -1@[x0, x1], rather than -1@[x0, 24]
      skip_whitespace_from(pos);
      pos = cur_pos_;
      if (parse_register(pos, new_pos, index_reg_name) == false)
        return error_return(pos, pos);
      dest->index_register_name_ = index_reg_name;
      dest->scale_ = 1;
      dest->deref_offset_ = 0;
    }
  }
  if (arg_[new_pos] != ']')
    return error_return(new_pos, new_pos);
  new_pos++;
  return true;
}

bool ArgumentParser_aarch64::parse(Argument *dest) {
  if (done())
    return false;

  // Support the following argument patterns:
  //   [-]<size>@<value>, [-]<size>@<reg>, [-]<size>@[<reg>], or
  //   [-]<size>@[<reg>,<offset>]
  //   [-]<size>@[<reg>,<index_reg>]
  ssize_t cur_pos = cur_pos_, new_pos;
  optional<int> arg_size;

  // Parse [-]<size>
  if (parse_size(cur_pos, new_pos, &arg_size) == false)
    return false;
  dest->arg_size_ = arg_size;

  // Make sure '@' present
  if (arg_[new_pos] != '@')
    return error_return(new_pos, new_pos);
  cur_pos = new_pos + 1;

  if (arg_[cur_pos] == 'x' || arg_[cur_pos] == 's') {
    // Parse ...@<reg>
    std::string reg_name;
    if (parse_register(cur_pos, new_pos, reg_name) == false)
      return false;

    cur_pos_ = new_pos;
    dest->base_register_name_ = reg_name;
  } else if (arg_[cur_pos] == '[') {
    // Parse ...@[<reg>], ...@[<reg,<offset>] and ...@[<reg>,<index_reg>]
    if (parse_mem(cur_pos + 1, new_pos, dest) == false)
      return false;
    cur_pos_ = new_pos;
  } else {
    // Parse ...@<value>
    optional<long long> val;
    new_pos = parse_number(cur_pos, &val);
    if (cur_pos == new_pos)
      return error_return(cur_pos, cur_pos);
    cur_pos_ = new_pos;
    dest->constant_ = val;
  }

  skip_whitespace_from(cur_pos_);
  return true;
}

bool ArgumentParser_loongarch64::parse_register(ssize_t pos, ssize_t &new_pos,
						std::string &reg_name) {
  if (arg_[pos] == '$' && arg_[pos + 1] == 'r') {
    optional<int> reg_num;
    new_pos = parse_number(pos + 2, &reg_num);
    if (new_pos == pos + 2 || *reg_num < 0 || *reg_num > 31)
      return error_return(pos + 2, pos + 2);

    if (*reg_num == 3) {
      reg_name = "sp";
    } else {
      reg_name = "regs[" + std::to_string(reg_num.value()) + "]";
    }
    return true;
  } else if (arg_[pos] == 's' && arg_[pos + 1] == 'p') {
    reg_name = "sp";
    new_pos = pos + 2;
    return true;
  } else {
    return error_return(pos, pos);
  }
}

bool ArgumentParser_loongarch64::parse_size(ssize_t pos, ssize_t &new_pos,
					    optional<int> *arg_size) {
  int abs_arg_size;

  new_pos = parse_number(pos, arg_size);
  if (new_pos == pos)
    return error_return(pos, pos);

  abs_arg_size = abs(arg_size->value());
  if (abs_arg_size != 1 && abs_arg_size != 2 && abs_arg_size != 4 &&
      abs_arg_size != 8)
    return error_return(pos, pos);
  return true;
}

bool ArgumentParser_loongarch64::parse_mem(ssize_t pos, ssize_t &new_pos,
					   Argument *dest) {
  std::string base_reg_name, index_reg_name;

  if (parse_register(pos, new_pos, base_reg_name) == false)
    return false;
  dest->base_register_name_ = base_reg_name;

  if (arg_[new_pos] == ',') {
    pos = new_pos + 1;
    new_pos = parse_number(pos, &dest->deref_offset_);
    if (new_pos == pos) {
      // offset isn't a number, so it should be a reg,
      // which looks like: -1@[$r0, $r1], rather than -1@[$r0, 24]
      skip_whitespace_from(pos);
      pos = cur_pos_;
      if (parse_register(pos, new_pos, index_reg_name) == false)
        return error_return(pos, pos);
      dest->index_register_name_ = index_reg_name;
      dest->scale_ = 1;
      dest->deref_offset_ = 0;
    }
  }
  if (arg_[new_pos] != ']')
    return error_return(new_pos, new_pos);
  new_pos++;
  return true;
}

bool ArgumentParser_loongarch64::parse(Argument *dest) {
  if (done())
    return false;

  // Support the following argument patterns:
  //   [-]<size>@<value>, [-]<size>@<reg>, [-]<size>@[<reg>], or
  //   [-]<size>@[<reg>,<offset>]
  //   [-]<size>@[<reg>,<index_reg>]
  ssize_t cur_pos = cur_pos_, new_pos;
  optional<int> arg_size;

  // Parse [-]<size>
  if (parse_size(cur_pos, new_pos, &arg_size) == false)
    return false;
  dest->arg_size_ = arg_size;

  // Make sure '@' present
  if (arg_[new_pos] != '@')
    return error_return(new_pos, new_pos);
  cur_pos = new_pos + 1;

  if (arg_[cur_pos] == '$' || arg_[cur_pos] == 's') {
    // Parse ...@<reg>
    std::string reg_name;
    if (parse_register(cur_pos, new_pos, reg_name) == false)
      return false;

    cur_pos_ = new_pos;
    dest->base_register_name_ = reg_name;
  } else if (arg_[cur_pos] == '[') {
    // Parse ...@[<reg>], ...@[<reg,<offset>] and ...@[<reg>,<index_reg>]
    if (parse_mem(cur_pos + 1, new_pos, dest) == false)
      return false;
    cur_pos_ = new_pos;
  } else {
    // Parse ...@<value>
    optional<long long> val;
    new_pos = parse_number(cur_pos, &val);
    if (cur_pos == new_pos)
      return error_return(cur_pos, cur_pos);
    cur_pos_ = new_pos;
    dest->constant_ = val;
  }

  skip_whitespace_from(cur_pos_);
  return true;
}

bool ArgumentParser_powerpc64::parse(Argument *dest) {
  if (done())
    return false;

  bool matched;
  std::smatch matches;
  std::string arg_str(&arg_[cur_pos_]);
  std::regex arg_n_regex("^(\\-?[1248])\\@");
  // Operands with constants of form iNUM or i-NUM
  std::regex arg_op_regex_const("^i(\\-?[0-9]+)( +|$)");
  // Operands with register only of form REG or %rREG
  std::regex arg_op_regex_reg("^(?:%r)?([1-2]?[0-9]|3[0-1])( +|$)");
  // Operands with a base register and an offset of form
  // NUM(REG) or -NUM(REG) or NUM(%rREG) or -NUM(%rREG)
  std::regex arg_op_regex_breg_off(
        "^(\\-?[0-9]+)\\((?:%r)?([1-2]?[0-9]|3[0-1])\\)( +|$)");
  // Operands with a base register and an index register
  // of form REG,REG or %rREG,%rREG
  std::regex arg_op_regex_breg_ireg(
        "^(?:%r)?([1-2]?[0-9]|3[0-1])\\,(?:%r)?([1-2]?[0-9]|3[0-1])( +|$)");

  matched = std::regex_search(arg_str, matches, arg_n_regex);
  if (matched) {
    dest->arg_size_ = stoi(matches.str(1));
    cur_pos_ += matches.length(0);
    arg_str = &arg_[cur_pos_];

    if (std::regex_search(arg_str, matches, arg_op_regex_const)) {
      dest->constant_ = (long long)stoull(matches.str(1));
    } else if (std::regex_search(arg_str, matches, arg_op_regex_reg)) {
      dest->base_register_name_ = "gpr[" + matches.str(1) + "]";
    } else if (std::regex_search(arg_str, matches, arg_op_regex_breg_off)) {
      dest->deref_offset_ = stoi(matches.str(1));
      dest->base_register_name_ = "gpr[" + matches.str(2) + "]";
    } else if (std::regex_search(arg_str, matches, arg_op_regex_breg_ireg)) {
      dest->deref_offset_ = 0; // In powerpc64, such operands contain a base
                               // register and an index register which are
                               // part of an indexed load/store operation.
                               // Even if no offset value is present, this
                               // is required by Argument::assign_to_local()
                               // in order to generate code for reading the
                               // argument. So, this is set to zero.
      dest->base_register_name_ = "gpr[" + matches.str(1) + "]";
      dest->index_register_name_ = "gpr[" + matches.str(2) + "]";
      dest->scale_ = abs(*dest->arg_size_);
    } else {
      matched = false;
    }
  }

  if (!matched) {
    print_error(cur_pos_);
    skip_until_whitespace_from(cur_pos_);
    skip_whitespace_from(cur_pos_);
    return false;
  }

  cur_pos_ += matches.length(0);
  skip_whitespace_from(cur_pos_);
  return true;
}

bool ArgumentParser_s390x::parse(Argument *dest) {
  if (done())
    return false;

  bool matched;
  std::cmatch matches;
#define S390X_IMM "(-?[0-9]+)"
  std::regex arg_n_regex("^" S390X_IMM "@");
  // <imm>
  std::regex arg_op_regex_imm("^" S390X_IMM "(?: +|$)");
  // %r<N>
#define S390X_REG "%r([0-9]|1[0-5])"
  std::regex arg_op_regex_reg("^" S390X_REG "(?: +|$)");
  // <disp>(%r<N>,%r<N>)
  std::regex arg_op_regex_mem("^" S390X_IMM "?\\(" S390X_REG
                              "(?:," S390X_REG ")?\\)(?: +|$)");
#undef S390X_IMM
#undef S390X_REG

  matched = std::regex_search(arg_ + cur_pos_, matches, arg_n_regex);
  if (matched) {
    dest->arg_size_ = stoi(matches.str(1));
    cur_pos_ += matches.length(0);

    if (std::regex_search(arg_ + cur_pos_, matches, arg_op_regex_imm)) {
      dest->constant_ = (long long)stoull(matches.str(1));
    } else if (std::regex_search(arg_ + cur_pos_, matches, arg_op_regex_reg)) {
      dest->base_register_name_ = "gprs[" + matches.str(1) + "]";
    } else if (std::regex_search(arg_ + cur_pos_, matches, arg_op_regex_mem)) {
      if (matches.length(1) > 0) {
        dest->deref_offset_ = stoi(matches.str(1));
      }
      dest->base_register_name_ = "gprs[" + matches.str(2) + "]";
      if (matches.length(3) > 0) {
        dest->index_register_name_ = "gprs[" + matches.str(3) + "]";
      }
    } else {
      matched = false;
    }
  }

  if (!matched) {
    print_error(cur_pos_);
    skip_until_whitespace_from(cur_pos_);
    skip_whitespace_from(cur_pos_);
    return false;
  }

  cur_pos_ += matches.length(0);
  skip_whitespace_from(cur_pos_);
  return true;
}

ssize_t ArgumentParser_x64::parse_identifier(ssize_t pos,
                                             optional<std::string> *result) {
  if (isalpha(arg_[pos]) || arg_[pos] == '_') {
    ssize_t start = pos++;
    while (isalnum(arg_[pos]) || arg_[pos] == '_') pos++;
    if (pos - start)
      result->emplace(arg_ + start, pos - start);
  }
  return pos;
}

ssize_t ArgumentParser_x64::parse_register(ssize_t pos, std::string &name,
                                           int &size) {
  ssize_t start = ++pos;
  if (arg_[start - 1] != '%')
    return -start;

  while (isalnum(arg_[pos])) pos++;

  std::string regname(arg_ + start, pos - start);
  if (!normalize_register(&regname, &size))
    return -start;

  name = regname;
  return pos;
}

ssize_t ArgumentParser_x64::parse_base_register(ssize_t pos, Argument *dest) {
  int size;
  std::string name;
  ssize_t res = parse_register(pos, name, size);
  if (res < 0)
      return res;

  dest->base_register_name_ = name;
  if (!dest->arg_size_)
    dest->arg_size_ = size;

  return res;
}

ssize_t ArgumentParser_x64::parse_index_register(ssize_t pos, Argument *dest) {
  int size;
  std::string name;
  ssize_t res = parse_register(pos, name, size);
  if (res < 0)
      return res;

  dest->index_register_name_ = name;

  return res;
}

ssize_t ArgumentParser_x64::parse_scale(ssize_t pos, Argument *dest) {
  return parse_number(pos, &dest->scale_);
}

ssize_t ArgumentParser_x64::parse_expr(ssize_t pos, Argument *dest) {
  if (arg_[pos] == '$')
    return parse_number(pos + 1, &dest->constant_);

  if (arg_[pos] == '%')
    return parse_base_register(pos, dest);

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
    if (arg_[pos] == '+' || arg_[pos] == '-') {
      pos = parse_number(pos, &dest->deref_offset_);
    }
  }

  if (arg_[pos] != '(')
    return -pos;

  pos = parse_base_register(pos + 1, dest);
  if (pos < 0)
    return pos;

  if (arg_[pos] == ',') {
    pos = parse_index_register(pos + 1, dest);
    if (pos < 0)
      return pos;

    if (arg_[pos] == ',') {
      pos = parse_scale(pos + 1, dest);
      if (pos < 0)
        return pos;
    }
  }

  return (arg_[pos] == ')') ? pos + 1 : -pos;
}

ssize_t ArgumentParser_x64::parse_1(ssize_t pos, Argument *dest) {
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

bool ArgumentParser_x64::parse(Argument *dest) {
  if (done())
    return false;

  ssize_t res = parse_1(cur_pos_, dest);
  if (res < 0)
    return error_return(-res, -res + 1);
  if (!isspace(arg_[res]) && arg_[res] != '\0')
    return error_return(res, res);
  skip_whitespace_from(res);
  return true;
}

const std::unordered_map<std::string, ArgumentParser_x64::RegInfo>
    ArgumentParser_x64::registers_ = {
        {"rax", {X64_REG_A, 8}},   {"eax", {X64_REG_A, 4}},
        {"ax", {X64_REG_A, 2}},    {"al", {X64_REG_A, 1}},

        {"rbx", {X64_REG_B, 8}},   {"ebx", {X64_REG_B, 4}},
        {"bx", {X64_REG_B, 2}},    {"bl", {X64_REG_B, 1}},

        {"rcx", {X64_REG_C, 8}},   {"ecx", {X64_REG_C, 4}},
        {"cx", {X64_REG_C, 2}},    {"cl", {X64_REG_C, 1}},

        {"rdx", {X64_REG_D, 8}},   {"edx", {X64_REG_D, 4}},
        {"dx", {X64_REG_D, 2}},    {"dl", {X64_REG_D, 1}},

        {"rsi", {X64_REG_SI, 8}},  {"esi", {X64_REG_SI, 4}},
        {"si", {X64_REG_SI, 2}},   {"sil", {X64_REG_SI, 1}},

        {"rdi", {X64_REG_DI, 8}},  {"edi", {X64_REG_DI, 4}},
        {"di", {X64_REG_DI, 2}},   {"dil", {X64_REG_DI, 1}},

        {"rbp", {X64_REG_BP, 8}},  {"ebp", {X64_REG_BP, 4}},
        {"bp", {X64_REG_BP, 2}},   {"bpl", {X64_REG_BP, 1}},

        {"rsp", {X64_REG_SP, 8}},  {"esp", {X64_REG_SP, 4}},
        {"sp", {X64_REG_SP, 2}},   {"spl", {X64_REG_SP, 1}},

        {"r8", {X64_REG_8, 8}},    {"r8d", {X64_REG_8, 4}},
        {"r8w", {X64_REG_8, 2}},   {"r8b", {X64_REG_8, 1}},

        {"r9", {X64_REG_9, 8}},    {"r9d", {X64_REG_9, 4}},
        {"r9w", {X64_REG_9, 2}},   {"r9b", {X64_REG_9, 1}},

        {"r10", {X64_REG_10, 8}},  {"r10d", {X64_REG_10, 4}},
        {"r10w", {X64_REG_10, 2}}, {"r10b", {X64_REG_10, 1}},

        {"r11", {X64_REG_11, 8}},  {"r11d", {X64_REG_11, 4}},
        {"r11w", {X64_REG_11, 2}}, {"r11b", {X64_REG_11, 1}},

        {"r12", {X64_REG_12, 8}},  {"r12d", {X64_REG_12, 4}},
        {"r12w", {X64_REG_12, 2}}, {"r12b", {X64_REG_12, 1}},

        {"r13", {X64_REG_13, 8}},  {"r13d", {X64_REG_13, 4}},
        {"r13w", {X64_REG_13, 2}}, {"r13b", {X64_REG_13, 1}},

        {"r14", {X64_REG_14, 8}},  {"r14d", {X64_REG_14, 4}},
        {"r14w", {X64_REG_14, 2}}, {"r14b", {X64_REG_14, 1}},

        {"r15", {X64_REG_15, 8}},  {"r15d", {X64_REG_15, 4}},
        {"r15w", {X64_REG_15, 2}}, {"r15b", {X64_REG_15, 1}},

        {"rip", {X64_REG_RIP, 8}},

        {"xmm0", {X64_REG_XMM0, 16}},
        {"xmm1", {X64_REG_XMM1, 16}},
        {"xmm2", {X64_REG_XMM2, 16}},
        {"xmm3", {X64_REG_XMM3, 16}},
        {"xmm4", {X64_REG_XMM4, 16}},
        {"xmm5", {X64_REG_XMM5, 16}},
        {"xmm6", {X64_REG_XMM6, 16}},
        {"xmm7", {X64_REG_XMM7, 16}},
        {"xmm8", {X64_REG_XMM8, 16}},
        {"xmm9", {X64_REG_XMM9, 16}},
        {"xmm10", {X64_REG_XMM10, 16}},
        {"xmm11", {X64_REG_XMM11, 16}},
        {"xmm12", {X64_REG_XMM12, 16}},
        {"xmm13", {X64_REG_XMM13, 16}},
        {"xmm14", {X64_REG_XMM14, 16}},
        {"xmm15", {X64_REG_XMM15, 16}},
};

void ArgumentParser_x64::reg_to_name(std::string *norm, Register reg) {
  switch (reg) {
  case X64_REG_A:
    *norm = "ax";
    break;
  case X64_REG_B:
    *norm = "bx";
    break;
  case X64_REG_C:
    *norm = "cx";
    break;
  case X64_REG_D:
    *norm = "dx";
    break;

  case X64_REG_SI:
    *norm = "si";
    break;
  case X64_REG_DI:
    *norm = "di";
    break;
  case X64_REG_BP:
    *norm = "bp";
    break;
  case X64_REG_SP:
    *norm = "sp";
    break;

  case X64_REG_8:
    *norm = "r8";
    break;
  case X64_REG_9:
    *norm = "r9";
    break;
  case X64_REG_10:
    *norm = "r10";
    break;
  case X64_REG_11:
    *norm = "r11";
    break;
  case X64_REG_12:
    *norm = "r12";
    break;
  case X64_REG_13:
    *norm = "r13";
    break;
  case X64_REG_14:
    *norm = "r14";
    break;
  case X64_REG_15:
    *norm = "r15";
    break;

  case X64_REG_RIP:
    *norm = "ip";
    break;

  case X64_REG_XMM0:
    *norm = "xmm0";
    break;
  case X64_REG_XMM1:
    *norm = "xmm1";
    break;
  case X64_REG_XMM2:
    *norm = "xmm2";
    break;
  case X64_REG_XMM3:
    *norm = "xmm3";
    break;
  case X64_REG_XMM4:
    *norm = "xmm4";
    break;
  case X64_REG_XMM5:
    *norm = "xmm5";
    break;
  case X64_REG_XMM6:
    *norm = "xmm6";
    break;
  case X64_REG_XMM7:
    *norm = "xmm7";
    break;
  case X64_REG_XMM8:
    *norm = "xmm8";
    break;
  case X64_REG_XMM9:
    *norm = "xmm9";
    break;
  case X64_REG_XMM10:
    *norm = "xmm10";
    break;
  case X64_REG_XMM11:
    *norm = "xmm11";
    break;
  case X64_REG_XMM12:
    *norm = "xmm12";
    break;
  case X64_REG_XMM13:
    *norm = "xmm13";
    break;
  case X64_REG_XMM14:
    *norm = "xmm14";
    break;
  case X64_REG_XMM15:
    *norm = "xmm15";
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
