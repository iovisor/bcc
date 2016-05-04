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
             uint64_t semaphore)
    : bin_path_(bin_path),
      provider_(provider),
      name_(name),
      semaphore_(semaphore) {}

bool Probe::in_shared_object() {
  if (!in_shared_object_)
    in_shared_object_ = (bcc_elf_is_shared_obj(bin_path_.c_str()) == 1);
  return in_shared_object_.value();
}

bool Probe::resolve_global_address(uint64_t *global, const uint64_t addr,
                                   optional<int> pid) {
  if (in_shared_object()) {
    return (pid &&
            bcc_resolve_global_addr(*pid, bin_path_.c_str(), addr, global) ==
                0);
  }

  *global = addr;
  return true;
}

bool Probe::lookup_semaphore_addr(uint64_t *address, int pid) {
  auto it = semaphores_.find(pid);
  if (it != semaphores_.end()) {
    *address = it->second;
    return true;
  }

  if (!resolve_global_address(address, semaphore_, pid))
    return false;

  semaphores_[pid] = *address;
  return true;
}

bool Probe::add_to_semaphore(int pid, int16_t val) {
  uint64_t address;
  if (!lookup_semaphore_addr(&address, pid))
    return false;

  std::string procmem = tfm::format("/proc/%d/mem", pid);
  int memfd = ::open(procmem.c_str(), O_RDWR);
  if (memfd < 0)
    return false;

  int16_t original;  // TODO: should this be unsigned?

  if (::lseek(memfd, static_cast<off_t>(address), SEEK_SET) < 0 ||
      ::read(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  original = original + val;

  if (::lseek(memfd, static_cast<off_t>(address), SEEK_SET) < 0 ||
      ::write(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  ::close(memfd);
  return true;
}

bool Probe::enable(int pid) {
  if (enabled_semaphores_.find(pid) != enabled_semaphores_.end())
    return true;

  if (!add_to_semaphore(pid, +1))
    return false;

  enabled_semaphores_.emplace(pid, std::move(ProcStat(pid)));
  return true;
}

bool Probe::disable(int pid) {
  auto it = enabled_semaphores_.find(pid);
  if (it == enabled_semaphores_.end())
    return false;

  bool result = true;
  if (!it->second.is_stale())
    result = add_to_semaphore(pid, -1);

  enabled_semaphores_.erase(it);
  return result;
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

bool Probe::usdt_getarg(std::ostream &stream,
    const std::string &fn_name, const optional<int> &pid) {
  const size_t arg_count = locations_[0].arguments_.size();

  if (arg_count == 0)
    return true;

  for (size_t arg_n = 0; arg_n < arg_count; ++arg_n) {
    std::string ctype = largest_arg_type(arg_n);
    std::string cptr = tfm::format("*((%s *)dest)", ctype);

    tfm::format(stream,
        "static inline int _bpf_readarg_%s_%d("
        "struct pt_regs *ctx, void *dest, size_t len) {\n"
        "  if (len != sizeof(%s)) return -1;\n",
        fn_name, arg_n + 1, ctype);

    if (locations_.size() == 1) {
      Location &location = locations_.front();
      stream << "  ";
      if (!location.arguments_[arg_n].assign_to_local(stream, cptr,
                                                      bin_path_, pid))
        return false;
      stream << "\n  return 0;\n}\n";
    } else {
      stream << "  switch(ctx->ip) {\n";
      for (Location &location : locations_) {
        uint64_t global_address;

        if (!resolve_global_address(&global_address, location.address_, pid))
          return false;

        tfm::format(stream, "  case 0x%xULL: ", global_address);
        if (!location.arguments_[arg_n].assign_to_local(stream, cptr,
                                                        bin_path_, pid))
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

Probe *Context::get(const std::string &probe_name) const {
  for (Probe *p : probes_) {
    if (p->name_ == probe_name)
      return p;
  }
  return nullptr;
}

bool Context::generate_usdt_args(std::ostream &stream) {
  stream << "#include <uapi/linux/ptrace.h>\n";
  for (auto &p : uprobes_) {
    if (!p.first->usdt_getarg(stream, p.second, pid_))
      return false;
  }
  return true;
}

bool Context::enable_probe(const std::string &probe_name,
                           const std::string &fn_name) {
  Probe *p = get(probe_name);
  if (!p)
    return false;

  if (p->need_enable()) {
    if (!pid_ || !p->enable(pid_.value()))
      return false;
  }

  uprobes_.emplace_back(p, fn_name);
  return true;
}

void Context::each_uprobe(each_uprobe_cb callback) {
  for (auto &p : uprobes_) {
    for (Probe::Location &loc : p.first->locations_) {
      callback(p.first->bin_path_.c_str(), p.second.c_str(), loc.address_,
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

Context::Context(int pid) : pid_(pid), loaded_(false) {
  if (bcc_procutils_each_module(pid, _each_module, this) == 0)
    loaded_ = true;
}

Context::~Context() {
  for (Probe *p : probes_) {
    if (pid_ && p->enabled())
      p->disable(pid_.value());
    delete p;
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
