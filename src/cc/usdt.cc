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
#include <sstream>

#include "bcc_elf.h"
#include "usdt.h"
#include "vendor/tinyformat.hpp"

namespace USDT {

Probe::Location::Location(uint64_t addr, const char *arg_fmt) : address_(addr) {
  ArgumentParser_x64 parser(arg_fmt);
  while (!parser.done()) {
    Argument *arg = new Argument();
    if (!parser.parse(arg)) {
      delete arg;  // TODO: report error
      continue;
    }
    arguments_.push_back(arg);
  }
}

Probe::Probe(const char *bin_path, const char *provider, const char *name,
             uint64_t semaphore)
    : bin_path_(bin_path),
      provider_(provider),
      name_(name),
      semaphore_(semaphore) {}

const std::string &Probe::usdt_thunks(const std::string &prefix) {
  if (!gen_thunks_.empty())
    return gen_thunks_;

  std::ostringstream stream;
  for (size_t i = 0; i < locations_.size(); ++i) {
    tfm::format(
        stream,
        "int %s_thunk_%d(struct pt_regs *ctx) { return %s(ctx, %d); }\n",
        prefix, i, prefix, i);
  }

  gen_thunks_ = stream.str();
  return gen_thunks_;
}

const std::string &Probe::usdt_cases(const optional<int> &pid) {
  if (!gen_cases_.empty())
    return gen_cases_;

  std::ostringstream stream;
  size_t arg_count = locations_[0].arguments_.size();

  for (size_t arg_n = 0; arg_n < arg_count; ++arg_n) {
    Argument *largest = nullptr;
    for (Location &location : locations_) {
      Argument *candidate = location.arguments_[arg_n];
      if (!largest || candidate->arg_size() > largest->arg_size())
        largest = candidate;
    }

    tfm::format(stream, "        %s arg%d = 0;\n", largest->ctype(), arg_n + 1);
  }

  for (size_t loc_n = 0; loc_n < locations_.size(); ++loc_n) {
    Location &location = locations_[loc_n];
    tfm::format(stream, "if (__loc_id == %d) {\n", loc_n);

    for (size_t arg_n = 0; arg_n < location.arguments_.size(); ++arg_n) {
      Argument *arg = location.arguments_[arg_n];
      arg->assign_to_local(stream, tfm::format("arg%d", arg_n + 1), bin_path_,
                           pid);
    }
    stream << "}\n";
  }

  gen_cases_ = stream.str();
  return gen_cases_;
}

void Probe::add_location(uint64_t addr, const char *fmt) {
  locations_.emplace_back(addr, fmt);
}

void Context::_each_probe(const char *binpath, const struct bcc_elf_usdt *probe,
                          void *p) {
  Context *ctx = static_cast<Context *>(p);
  ctx->add_probe(binpath, probe);
}

void Context::add_probe(const char *binpath, const struct bcc_elf_usdt *probe) {
  Probe *found_probe = nullptr;

  for (Probe *p : probes_) {
    if (p->provider_ == probe->provider && p->name_ == probe->name) {
      found_probe = p;
      break;
    }
  }

  if (!found_probe) {
    found_probe =
        new Probe(binpath, probe->provider, probe->name, probe->semaphore);
    probes_.push_back(found_probe);
  }

  found_probe->add_location(probe->pc, probe->arg_fmt);
}

void Context::add_probes(const std::string &bin_path) {
  bcc_elf_foreach_usdt(bin_path.c_str(), _each_probe, this);
}

Context::Context(const std::string &bin_path) { add_probes(bin_path); }

Context::Context(int pid) {}
}
