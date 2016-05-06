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
#include <cstring>
#include <sstream>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_proc.h"
#include "usdt.h"
#include "vendor/tinyformat.hpp"

namespace USDT {

Probe::Location::Location(uint64_t addr, const char *arg_fmt) : address_(addr) {
  ArgumentParser_x64 parser(arg_fmt);
  while (!parser.done()) {
    Argument arg;
    if (!parser.parse(&arg))
      continue;
    arguments_.push_back(std::move(arg));
  }
}

Probe::Probe(const char *bin_path, const char *provider, const char *name,
             uint64_t semaphore, const optional<int> &pid)
    : bin_path_(bin_path),
      provider_(provider),
      name_(name),
      semaphore_(semaphore),
      pid_(pid) {}

bool Probe::in_shared_object() {
  if (!in_shared_object_)
    in_shared_object_ = (bcc_elf_is_shared_obj(bin_path_.c_str()) == 1);
  return in_shared_object_.value();
}

bool Probe::resolve_global_address(uint64_t *global, const uint64_t addr) {
  if (in_shared_object()) {
    return (pid_ &&
            !bcc_resolve_global_addr(*pid_, bin_path_.c_str(), addr, global));
  }

  *global = addr;
  return true;
}

bool Probe::add_to_semaphore(int16_t val) {
  assert(pid_ && attached_semaphore_);

  if (!attached_semaphore_) {
    uint64_t addr;
    if (!resolve_global_address(&addr, semaphore_))
      return false;
    attached_semaphore_ = addr;
  }

  off_t address = static_cast<off_t>(attached_semaphore_.value());

  std::string procmem = tfm::format("/proc/%d/mem", pid_.value());
  int memfd = ::open(procmem.c_str(), O_RDWR);
  if (memfd < 0)
    return false;

  int16_t original;

  if (::lseek(memfd, address, SEEK_SET) < 0 ||
      ::read(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  original = original + val;

  if (::lseek(memfd, address, SEEK_SET) < 0 ||
      ::write(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  ::close(memfd);
  return true;
}

bool Probe::enable(const std::string &fn_name) {
  if (attached_to_)
    return false;

  if (need_enable()) {
    if (!pid_)
      return false;

    if (!add_to_semaphore(+1))
      return false;
  }

  attached_to_ = fn_name;
  return true;
}

bool Probe::disable() {
  if (!attached_to_)
    return false;

  attached_to_ = nullopt;

  if (need_enable()) {
    assert(pid_);
    return add_to_semaphore(-1);
  }
  return true;
}

std::string Probe::largest_arg_type(size_t arg_n) {
  Argument *largest = nullptr;
  for (Location &location : locations_) {
    Argument *candidate = &location.arguments_[arg_n];
    if (!largest ||
        std::abs(candidate->arg_size()) > std::abs(largest->arg_size()))
      largest = candidate;
  }

  assert(largest);
  return largest->ctype();
}

bool Probe::usdt_getarg(std::ostream &stream) {
  const size_t arg_count = locations_[0].arguments_.size();

  if (!attached_to_)
    return false;

  if (arg_count == 0)
    return true;

  for (size_t arg_n = 0; arg_n < arg_count; ++arg_n) {
    std::string ctype = largest_arg_type(arg_n);
    std::string cptr = tfm::format("*((%s *)dest)", ctype);

    tfm::format(stream,
                "static inline int _bpf_readarg_%s_%d("
                "struct pt_regs *ctx, void *dest, size_t len) {\n"
                "  if (len != sizeof(%s)) return -1;\n",
                attached_to_.value(), arg_n + 1, ctype);

    if (locations_.size() == 1) {
      Location &location = locations_.front();
      stream << "  ";
      if (!location.arguments_[arg_n].assign_to_local(stream, cptr, bin_path_,
                                                      pid_))
        return false;
      stream << "\n  return 0;\n}\n";
    } else {
      stream << "  switch(ctx->ip) {\n";
      for (Location &location : locations_) {
        uint64_t global_address;

        if (!resolve_global_address(&global_address, location.address_))
          return false;

        tfm::format(stream, "  case 0x%xULL: ", global_address);
        if (!location.arguments_[arg_n].assign_to_local(stream, cptr, bin_path_,
                                                        pid_))
          return false;

        stream << " return 0;\n";
      }
      stream << "  }\n";
      stream << "  return -1;\n}\n";
    }
  }
  return true;
}

void Probe::add_location(uint64_t addr, const char *fmt) {
  locations_.emplace_back(addr, fmt);
}

void Context::_each_probe(const char *binpath, const struct bcc_elf_usdt *probe,
                          void *p) {
  Context *ctx = static_cast<Context *>(p);
  ctx->add_probe(binpath, probe);
}

int Context::_each_module(const char *modpath, uint64_t, uint64_t, void *p) {
  bcc_elf_foreach_usdt(modpath, _each_probe, p);
  return 0;
}

void Context::add_probe(const char *binpath, const struct bcc_elf_usdt *probe) {
  for (auto &p : probes_) {
    if (p->provider_ == probe->provider && p->name_ == probe->name) {
      p->add_location(probe->pc, probe->arg_fmt);
      return;
    }
  }

  probes_.emplace_back(
      new Probe(binpath, probe->provider, probe->name, probe->semaphore, pid_));
  probes_.back()->add_location(probe->pc, probe->arg_fmt);
}

std::string Context::resolve_bin_path(const std::string &bin_path) {
  std::string result;

  if (char *which = bcc_procutils_which(bin_path.c_str())) {
    result = which;
    ::free(which);
  } else if (const char *which_so = bcc_procutils_which_so(bin_path.c_str())) {
    result = which_so;
  }

  return result;
}

Probe *Context::get(const std::string &probe_name) {
  for (auto &p : probes_) {
    if (p->name_ == probe_name)
      return p.get();
  }
  return nullptr;
}

bool Context::generate_usdt_args(std::ostream &stream) {
  stream << "#include <uapi/linux/ptrace.h>\n";
  for (auto &p : probes_) {
    if (p->enabled() && !p->usdt_getarg(stream))
      return false;
  }
  return true;
}

bool Context::enable_probe(const std::string &probe_name,
                           const std::string &fn_name) {
  if (pid_stat_ && pid_stat_->is_stale())
    return false;

  auto p = get(probe_name);
  return p && p->enable(fn_name);
}

void Context::each_uprobe(each_uprobe_cb callback) {
  for (auto &p : probes_) {
    if (!p->enabled())
      continue;

    for (Probe::Location &loc : p->locations_) {
      callback(p->bin_path_.c_str(), p->attached_to_->c_str(), loc.address_,
               pid_.value_or(-1));
    }
  }
}

Context::Context(const std::string &bin_path) : loaded_(false) {
  std::string full_path = resolve_bin_path(bin_path);
  if (!full_path.empty()) {
    if (bcc_elf_foreach_usdt(full_path.c_str(), _each_probe, this) == 0)
      loaded_ = true;
  }
}

Context::Context(int pid) : pid_(pid), pid_stat_(pid), loaded_(false) {
  if (bcc_procutils_each_module(pid, _each_module, this) == 0)
    loaded_ = true;
}

Context::~Context() {
  if (pid_stat_ && !pid_stat_->is_stale()) {
    for (auto &p : probes_) p->disable();
  }
}
}

extern "C" {
#include "bcc_usdt.h"

void *bcc_usdt_new_frompid(int pid) {
  USDT::Context *ctx = new USDT::Context(pid);
  if (!ctx->loaded()) {
    delete ctx;
    return nullptr;
  }
  return static_cast<void *>(ctx);
}

void *bcc_usdt_new_frompath(const char *path) {
  USDT::Context *ctx = new USDT::Context(path);
  if (!ctx->loaded()) {
    delete ctx;
    return nullptr;
  }
  return static_cast<void *>(ctx);
}

void bcc_usdt_close(void *usdt) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  delete ctx;
}

int bcc_usdt_enable_probe(void *usdt, const char *probe_name,
                          const char *fn_name) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  return ctx->enable_probe(probe_name, fn_name) ? 0 : -1;
}

char *bcc_usdt_genargs(void *usdt) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  std::ostringstream stream;
  if (!ctx->generate_usdt_args(stream))
    return nullptr;
  return strdup(stream.str().c_str());
}

void bcc_usdt_foreach_uprobe(void *usdt, bcc_usdt_uprobe_cb callback) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  ctx->each_uprobe(callback);
}
}
