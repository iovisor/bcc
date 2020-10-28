/*
 * Copyright (c) 2016 Facebook, Inc.
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

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <utility>
#include <vector>

#include "bcc_exception.h"
#include "bcc_elf.h"
#include "bcc_syms.h"
#include "bpf_module.h"
#include "common.h"
#include "libbpf.h"
#include "perf_reader.h"
#include "syms.h"
#include "table_storage.h"
#include "usdt.h"

#include "BPF.h"

namespace {
/*
 * Kernels ~4.20 and later support specifying the ref_ctr_offset as an argument
 * to attaching a uprobe, which negates the need to seek to this memory offset
 * in userspace to manage semaphores, as the kernel will do it for us.  This
 * helper function checks if this support is available by reading the uprobe
 * format for this value, added in a6ca88b241d5e929e6e60b12ad8cd288f0ffa
*/
bool uprobe_ref_ctr_supported() {
  const char *ref_ctr_pmu_path =
      "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset";
  const char *ref_ctr_pmu_expected = "config:32-63\0";
  char ref_ctr_pmu_fmt[64];  // in Linux source this buffer is compared vs
                             // PAGE_SIZE, but 64 is probably ample
  int fd = open(ref_ctr_pmu_path, O_RDONLY);
  if (fd < 0)
    return false;

  int ret = read(fd, ref_ctr_pmu_fmt, sizeof(ref_ctr_pmu_fmt));
  close(fd);
  if (ret < 0) {
    return false;
  }
  if (strncmp(ref_ctr_pmu_expected, ref_ctr_pmu_fmt,
              strlen(ref_ctr_pmu_expected)) == 0) {
    return true;
  }
  return false;
}
} // namespace

namespace ebpf {

std::string uint_to_hex(uint64_t value) {
  std::stringstream ss;
  ss << std::hex << value;
  return ss.str();
}

std::string sanitize_str(std::string str, bool (*validator)(char),
                         char replacement = '_') {
  for (size_t i = 0; i < str.length(); i++)
    if (!validator(str[i]))
      str[i] = replacement;
  return str;
}

StatusTuple BPF::init_usdt(const USDT& usdt) {
  USDT u(usdt);
  StatusTuple init_stp = u.init();
  if (init_stp.code() != 0) {
    return init_stp;
  }

  usdt_.push_back(std::move(u));
  all_bpf_program_ += usdt_.back().program_text_;
  return StatusTuple::OK();
}

void BPF::init_fail_reset() {
  usdt_.clear();
  all_bpf_program_ = "";
}

StatusTuple BPF::init(const std::string& bpf_program,
                      const std::vector<std::string>& cflags,
                      const std::vector<USDT>& usdt) {
  usdt_.reserve(usdt.size());
  for (const auto& u : usdt) {
    StatusTuple init_stp = init_usdt(u);
    if (init_stp.code() != 0) {
      init_fail_reset();
      return init_stp;
    }
  }

  auto flags_len = cflags.size();
  const char* flags[flags_len];
  for (size_t i = 0; i < flags_len; i++)
    flags[i] = cflags[i].c_str();

  all_bpf_program_ += bpf_program;
  if (bpf_module_->load_string(all_bpf_program_, flags, flags_len) != 0) {
    init_fail_reset();
    return StatusTuple(-1, "Unable to initialize BPF program");
  }

  return StatusTuple::OK();
};

BPF::~BPF() {
  auto res = detach_all();
  if (res.code() != 0)
    std::cerr << "Failed to detach all probes on destruction: " << std::endl
              << res.msg() << std::endl;
  bcc_free_buildsymcache(bsymcache_);
  bsymcache_ = NULL;
}

StatusTuple BPF::detach_all() {
  bool has_error = false;
  std::string error_msg;

  for (auto& it : kprobes_) {
    auto res = detach_kprobe_event(it.first, it.second);
    if (res.code() != 0) {
      error_msg += "Failed to detach kprobe event " + it.first + ": ";
      error_msg += res.msg() + "\n";
      has_error = true;
    }
  }

  for (auto& it : uprobes_) {
    auto res = detach_uprobe_event(it.first, it.second);
    if (res.code() != 0) {
      error_msg += "Failed to detach uprobe event " + it.first + ": ";
      error_msg += res.msg() + "\n";
      has_error = true;
    }
  }

  for (auto& it : tracepoints_) {
    auto res = detach_tracepoint_event(it.first, it.second);
    if (res.code() != 0) {
      error_msg += "Failed to detach Tracepoint " + it.first + ": ";
      error_msg += res.msg() + "\n";
      has_error = true;
    }
  }

  for (auto& it : raw_tracepoints_) {
    auto res = detach_raw_tracepoint_event(it.first, it.second);
    if (res.code() != 0) {
      error_msg += "Failed to detach Raw tracepoint " + it.first + ": ";
      error_msg += res.msg() + "\n";
      has_error = true;
    }
  }

  for (auto& it : perf_buffers_) {
    auto res = it.second->close_all_cpu();
    if (res.code() != 0) {
      error_msg += "Failed to close perf buffer " + it.first + ": ";
      error_msg += res.msg() + "\n";
      has_error = true;
    }
    delete it.second;
  }

  for (auto& it : perf_event_arrays_) {
    auto res = it.second->close_all_cpu();
    if (res.code() != 0) {
      error_msg += "Failed to close perf event array " + it.first + ": ";
      error_msg += res.msg() + "\n";
      has_error = true;
    }
    delete it.second;
  }

  for (auto& it : perf_events_) {
    auto res = detach_perf_event_all_cpu(it.second);
    if (res.code() != 0) {
      error_msg += res.msg() + "\n";
      has_error = true;
    }
  }

  for (auto& it : funcs_) {
    int res = close(it.second);
    if (res != 0) {
      error_msg += "Failed to unload BPF program for " + it.first + ": ";
      error_msg += std::string(std::strerror(errno)) + "\n";
      has_error = true;
    }
  }

  if (has_error)
    return StatusTuple(-1, error_msg);
  else
    return StatusTuple::OK();
}

StatusTuple BPF::attach_kprobe(const std::string& kernel_func,
                               const std::string& probe_func,
                               uint64_t kernel_func_offset,
                               bpf_probe_attach_type attach_type,
                               int maxactive) {
  std::string probe_event = get_kprobe_event(kernel_func, attach_type);
  if (kprobes_.find(probe_event) != kprobes_.end())
    return StatusTuple(-1, "kprobe %s already attached", probe_event.c_str());

  int probe_fd;
  TRY2(load_func(probe_func, BPF_PROG_TYPE_KPROBE, probe_fd));

  int res_fd = bpf_attach_kprobe(probe_fd, attach_type, probe_event.c_str(),
                                 kernel_func.c_str(), kernel_func_offset,
                                 maxactive);

  if (res_fd < 0) {
    TRY2(unload_func(probe_func));
    return StatusTuple(-1, "Unable to attach %skprobe for %s using %s",
                       attach_type_debug(attach_type).c_str(),
                       kernel_func.c_str(), probe_func.c_str());
  }

  open_probe_t p = {};
  p.perf_event_fd = res_fd;
  p.func = probe_func;
  kprobes_[probe_event] = std::move(p);
  return StatusTuple::OK();
}

StatusTuple BPF::attach_uprobe(const std::string& binary_path,
                               const std::string& symbol,
                               const std::string& probe_func,
                               uint64_t symbol_addr,
                               bpf_probe_attach_type attach_type, pid_t pid,
                               uint64_t symbol_offset,
                               uint32_t ref_ctr_offset) {

  if (symbol_addr != 0 && symbol_offset != 0)
    return StatusTuple(-1,
             "Attachng uprobe with addr %lx and offset %lx is not supported",
             symbol_addr, symbol_offset);

  std::string module;
  uint64_t offset;
  TRY2(check_binary_symbol(binary_path, symbol, symbol_addr, module, offset,
                           symbol_offset));

  std::string probe_event = get_uprobe_event(module, offset, attach_type, pid);
  if (uprobes_.find(probe_event) != uprobes_.end())
    return StatusTuple(-1, "uprobe %s already attached", probe_event.c_str());

  int probe_fd;
  TRY2(load_func(probe_func, BPF_PROG_TYPE_KPROBE, probe_fd));

  int res_fd = bpf_attach_uprobe(probe_fd, attach_type, probe_event.c_str(),
                                 binary_path.c_str(), offset, pid,
                                 ref_ctr_offset);

  if (res_fd < 0) {
    TRY2(unload_func(probe_func));
    return StatusTuple(
        -1,
        "Unable to attach %suprobe for binary %s symbol %s addr %lx "
        "offset %lx using %s\n",
        attach_type_debug(attach_type).c_str(), binary_path.c_str(),
        symbol.c_str(), symbol_addr, symbol_offset, probe_func.c_str());
  }

  open_probe_t p = {};
  p.perf_event_fd = res_fd;
  p.func = probe_func;
  uprobes_[probe_event] = std::move(p);
  return StatusTuple::OK();
}

StatusTuple BPF::attach_usdt_without_validation(const USDT& u, pid_t pid) {
  auto& probe = *static_cast<::USDT::Probe*>(u.probe_.get());
  if (!uprobe_ref_ctr_supported() && !probe.enable(u.probe_func_))
    return StatusTuple(-1, "Unable to enable USDT %s" + u.print_name());

  bool failed = false;
  std::string err_msg;
  int cnt = 0;
  for (const auto& loc : probe.locations_) {
    auto res = attach_uprobe(loc.bin_path_, std::string(), u.probe_func_,
                             loc.address_, BPF_PROBE_ENTRY, pid, 0,
                             probe.semaphore_offset());
    if (!res.ok()) {
      failed = true;
      err_msg += "USDT " + u.print_name() + " at " + loc.bin_path_ +
                  " address " + std::to_string(loc.address_);
      err_msg += ": " + res.msg() + "\n";
      break;
    }
    cnt++;
  }
  if (failed) {
    for (int i = 0; i < cnt; i++) {
      auto res = detach_uprobe(probe.locations_[i].bin_path_, std::string(),
                               probe.locations_[i].address_, BPF_PROBE_ENTRY, pid);
      if (!res.ok())
        err_msg += "During clean up: " + res.msg() + "\n";
    }
    return StatusTuple(-1, err_msg);
  } else {
    return StatusTuple::OK();
  }
}

StatusTuple BPF::attach_usdt(const USDT& usdt, pid_t pid) {
  for (const auto& u : usdt_) {
    if (u == usdt) {
      return attach_usdt_without_validation(u, pid);
    }
  }

  return StatusTuple(-1, "USDT %s not found", usdt.print_name().c_str());
}

StatusTuple BPF::attach_usdt_all() {
  for (const auto& u : usdt_) {
    auto res = attach_usdt_without_validation(u, -1);
    if (!res.ok()) {
      return res;
    }
  }

  return StatusTuple::OK();
}


StatusTuple BPF::attach_tracepoint(const std::string& tracepoint,
                                   const std::string& probe_func) {
  if (tracepoints_.find(tracepoint) != tracepoints_.end())
    return StatusTuple(-1, "Tracepoint %s already attached",
                       tracepoint.c_str());

  auto pos = tracepoint.find(":");
  if ((pos == std::string::npos) || (pos != tracepoint.rfind(":")))
    return StatusTuple(-1, "Unable to parse Tracepoint %s", tracepoint.c_str());
  std::string tp_category = tracepoint.substr(0, pos);
  std::string tp_name = tracepoint.substr(pos + 1);

  int probe_fd;
  TRY2(load_func(probe_func, BPF_PROG_TYPE_TRACEPOINT, probe_fd));

  int res_fd =
      bpf_attach_tracepoint(probe_fd, tp_category.c_str(), tp_name.c_str());

  if (res_fd < 0) {
    TRY2(unload_func(probe_func));
    return StatusTuple(-1, "Unable to attach Tracepoint %s using %s",
                       tracepoint.c_str(), probe_func.c_str());
  }

  open_probe_t p = {};
  p.perf_event_fd = res_fd;
  p.func = probe_func;
  tracepoints_[tracepoint] = std::move(p);
  return StatusTuple::OK();
}

StatusTuple BPF::attach_raw_tracepoint(const std::string& tracepoint, const std::string& probe_func) {
  if (raw_tracepoints_.find(tracepoint) != raw_tracepoints_.end())
    return StatusTuple(-1, "Raw tracepoint %s already attached",
                       tracepoint.c_str());

  int probe_fd;
  TRY2(load_func(probe_func, BPF_PROG_TYPE_RAW_TRACEPOINT, probe_fd));

  int res_fd = bpf_attach_raw_tracepoint(probe_fd, tracepoint.c_str());

  if (res_fd < 0) {
    TRY2(unload_func(probe_func));
    return StatusTuple(-1, "Unable to attach Raw tracepoint %s using %s",
                       tracepoint.c_str(), probe_func.c_str());
  }

  open_probe_t p = {};
  p.perf_event_fd = res_fd;
  p.func = probe_func;
  raw_tracepoints_[tracepoint] = std::move(p);
  return StatusTuple::OK();
}

StatusTuple BPF::attach_perf_event(uint32_t ev_type, uint32_t ev_config,
                                   const std::string& probe_func,
                                   uint64_t sample_period, uint64_t sample_freq,
                                   pid_t pid, int cpu, int group_fd) {
  auto ev_pair = std::make_pair(ev_type, ev_config);
  if (perf_events_.find(ev_pair) != perf_events_.end())
    return StatusTuple(-1, "Perf event type %d config %d already attached",
                       ev_type, ev_config);

  int probe_fd;
  TRY2(load_func(probe_func, BPF_PROG_TYPE_PERF_EVENT, probe_fd));

  std::vector<int> cpus;
  if (cpu >= 0)
    cpus.push_back(cpu);
  else
    cpus = get_online_cpus();
  auto fds = new std::vector<std::pair<int, int>>();
  fds->reserve(cpus.size());
  for (int i : cpus) {
    int fd = bpf_attach_perf_event(probe_fd, ev_type, ev_config, sample_period,
                                   sample_freq, pid, i, group_fd);
    if (fd < 0) {
      for (const auto& it : *fds)
        close(it.second);
      delete fds;
      TRY2(unload_func(probe_func));
      return StatusTuple(-1, "Failed to attach perf event type %d config %d",
                         ev_type, ev_config);
    }
    fds->emplace_back(i, fd);
  }

  open_probe_t p = {};
  p.func = probe_func;
  p.per_cpu_fd = fds;
  perf_events_[ev_pair] = std::move(p);
  return StatusTuple::OK();
}

StatusTuple BPF::attach_perf_event_raw(void* perf_event_attr,
                                       const std::string& probe_func, pid_t pid,
                                       int cpu, int group_fd,
                                       unsigned long extra_flags) {
  auto attr = static_cast<struct perf_event_attr*>(perf_event_attr);
  auto ev_pair = std::make_pair(attr->type, attr->config);
  if (perf_events_.find(ev_pair) != perf_events_.end())
    return StatusTuple(-1, "Perf event type %d config %d already attached",
                       attr->type, attr->config);

  int probe_fd;
  TRY2(load_func(probe_func, BPF_PROG_TYPE_PERF_EVENT, probe_fd));

  std::vector<int> cpus;
  if (cpu >= 0)
    cpus.push_back(cpu);
  else
    cpus = get_online_cpus();
  auto fds = new std::vector<std::pair<int, int>>();
  fds->reserve(cpus.size());
  for (int i : cpus) {
    int fd = bpf_attach_perf_event_raw(probe_fd, attr, pid, i, group_fd,
                                       extra_flags);
    if (fd < 0) {
      for (const auto& it : *fds)
        close(it.second);
      delete fds;
      TRY2(unload_func(probe_func));
      return StatusTuple(-1, "Failed to attach perf event type %d config %d",
                         attr->type, attr->config);
    }
    fds->emplace_back(i, fd);
  }

  open_probe_t p = {};
  p.func = probe_func;
  p.per_cpu_fd = fds;
  perf_events_[ev_pair] = std::move(p);
  return StatusTuple::OK();
}

StatusTuple BPF::detach_kprobe(const std::string& kernel_func,
                               bpf_probe_attach_type attach_type) {
  std::string event = get_kprobe_event(kernel_func, attach_type);

  auto it = kprobes_.find(event);
  if (it == kprobes_.end())
    return StatusTuple(-1, "No open %skprobe for %s",
                       attach_type_debug(attach_type).c_str(),
                       kernel_func.c_str());

  TRY2(detach_kprobe_event(it->first, it->second));
  kprobes_.erase(it);
  return StatusTuple::OK();
}

StatusTuple BPF::detach_uprobe(const std::string& binary_path,
                               const std::string& symbol, uint64_t symbol_addr,
                               bpf_probe_attach_type attach_type, pid_t pid,
                               uint64_t symbol_offset) {
  std::string module;
  uint64_t offset;
  TRY2(check_binary_symbol(binary_path, symbol, symbol_addr, module, offset,
                           symbol_offset));

  std::string event = get_uprobe_event(module, offset, attach_type, pid);
  auto it = uprobes_.find(event);
  if (it == uprobes_.end())
    return StatusTuple(-1, "No open %suprobe for binary %s symbol %s addr %lx",
                       attach_type_debug(attach_type).c_str(),
                       binary_path.c_str(), symbol.c_str(), symbol_addr);

  TRY2(detach_uprobe_event(it->first, it->second));
  uprobes_.erase(it);
  return StatusTuple::OK();
}

StatusTuple BPF::detach_usdt_without_validation(const USDT& u, pid_t pid) {
  auto& probe = *static_cast<::USDT::Probe*>(u.probe_.get());
  bool failed = false;
  std::string err_msg;
  for (const auto& loc : probe.locations_) {
    auto res = detach_uprobe(loc.bin_path_, std::string(), loc.address_,
                             BPF_PROBE_ENTRY, pid);
    if (!res.ok()) {
      failed = true;
      err_msg += "USDT " + u.print_name() + " at " + loc.bin_path_ +
                  " address " + std::to_string(loc.address_);
      err_msg += ": " + res.msg() + "\n";
    }
  }

  if (!uprobe_ref_ctr_supported() && !probe.disable()) {
    failed = true;
    err_msg += "Unable to disable USDT " + u.print_name();
  }

  if (failed)
    return StatusTuple(-1, err_msg);
  else
    return StatusTuple::OK();
}

StatusTuple BPF::detach_usdt(const USDT& usdt, pid_t pid) {
  for (const auto& u : usdt_) {
    if (u == usdt) {
      return detach_usdt_without_validation(u, pid);
    }
  }

  return StatusTuple(-1, "USDT %s not found", usdt.print_name().c_str());
}

StatusTuple BPF::detach_usdt_all() {
  for (const auto& u : usdt_) {
    auto ret = detach_usdt_without_validation(u, -1);
    if (!ret.ok()) {
      return ret;
    }
  }

  return StatusTuple::OK();
}

StatusTuple BPF::detach_tracepoint(const std::string& tracepoint) {
  auto it = tracepoints_.find(tracepoint);
  if (it == tracepoints_.end())
    return StatusTuple(-1, "No open Tracepoint %s", tracepoint.c_str());

  TRY2(detach_tracepoint_event(it->first, it->second));
  tracepoints_.erase(it);
  return StatusTuple::OK();
}

StatusTuple BPF::detach_raw_tracepoint(const std::string& tracepoint) {
  auto it = raw_tracepoints_.find(tracepoint);
  if (it == raw_tracepoints_.end())
    return StatusTuple(-1, "No open Raw tracepoint %s", tracepoint.c_str());

  TRY2(detach_raw_tracepoint_event(it->first, it->second));
  raw_tracepoints_.erase(it);
  return StatusTuple::OK();
}

StatusTuple BPF::detach_perf_event(uint32_t ev_type, uint32_t ev_config) {
  auto it = perf_events_.find(std::make_pair(ev_type, ev_config));
  if (it == perf_events_.end())
    return StatusTuple(-1, "Perf Event type %d config %d not attached", ev_type,
                       ev_config);
  TRY2(detach_perf_event_all_cpu(it->second));
  perf_events_.erase(it);
  return StatusTuple::OK();
}

StatusTuple BPF::detach_perf_event_raw(void* perf_event_attr) {
  auto attr = static_cast<struct perf_event_attr*>(perf_event_attr);
  return detach_perf_event(attr->type, attr->config);
}

StatusTuple BPF::open_perf_event(const std::string& name, uint32_t type,
                                 uint64_t config) {
  if (perf_event_arrays_.find(name) == perf_event_arrays_.end()) {
    TableStorage::iterator it;
    if (!bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return StatusTuple(-1, "open_perf_event: unable to find table_storage %s",
                         name.c_str());
    perf_event_arrays_[name] = new BPFPerfEventArray(it->second);
  }
  auto table = perf_event_arrays_[name];
  TRY2(table->open_all_cpu(type, config));
  return StatusTuple::OK();
}

StatusTuple BPF::close_perf_event(const std::string& name) {
  auto it = perf_event_arrays_.find(name);
  if (it == perf_event_arrays_.end())
    return StatusTuple(-1, "Perf Event for %s not open", name.c_str());
  TRY2(it->second->close_all_cpu());
  return StatusTuple::OK();
}

StatusTuple BPF::open_perf_buffer(const std::string& name,
                                  perf_reader_raw_cb cb,
                                  perf_reader_lost_cb lost_cb, void* cb_cookie,
                                  int page_cnt) {
  if (perf_buffers_.find(name) == perf_buffers_.end()) {
    TableStorage::iterator it;
    if (!bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return StatusTuple(-1,
                         "open_perf_buffer: unable to find table_storage %s",
                         name.c_str());
    perf_buffers_[name] = new BPFPerfBuffer(it->second);
  }
  if ((page_cnt & (page_cnt - 1)) != 0)
    return StatusTuple(-1, "open_perf_buffer page_cnt must be a power of two");
  auto table = perf_buffers_[name];
  TRY2(table->open_all_cpu(cb, lost_cb, cb_cookie, page_cnt));
  return StatusTuple::OK();
}

StatusTuple BPF::close_perf_buffer(const std::string& name) {
  auto it = perf_buffers_.find(name);
  if (it == perf_buffers_.end())
    return StatusTuple(-1, "Perf buffer for %s not open", name.c_str());
  TRY2(it->second->close_all_cpu());
  return StatusTuple::OK();
}

BPFPerfBuffer* BPF::get_perf_buffer(const std::string& name) {
  auto it = perf_buffers_.find(name);
  return (it == perf_buffers_.end()) ? nullptr : it->second;
}

int BPF::poll_perf_buffer(const std::string& name, int timeout_ms) {
  auto it = perf_buffers_.find(name);
  if (it == perf_buffers_.end())
    return -1;
  return it->second->poll(timeout_ms);
}

StatusTuple BPF::load_func(const std::string& func_name, bpf_prog_type type,
                           int& fd) {
  if (funcs_.find(func_name) != funcs_.end()) {
    fd = funcs_[func_name];
    return StatusTuple::OK();
  }

  uint8_t* func_start = bpf_module_->function_start(func_name);
  if (!func_start)
    return StatusTuple(-1, "Can't find start of function %s",
                       func_name.c_str());
  size_t func_size = bpf_module_->function_size(func_name);

  int log_level = 0;
  if (flag_ & DEBUG_BPF_REGISTER_STATE)
    log_level = 2;
  else if (flag_ & DEBUG_BPF)
    log_level = 1;

  fd = bpf_module_->bcc_func_load(type, func_name.c_str(),
                     reinterpret_cast<struct bpf_insn*>(func_start), func_size,
                     bpf_module_->license(), bpf_module_->kern_version(),
                     log_level, nullptr, 0);

  if (fd < 0)
    return StatusTuple(-1, "Failed to load %s: %d", func_name.c_str(), fd);

  int ret = bpf_module_->annotate_prog_tag(
      func_name, fd, reinterpret_cast<struct bpf_insn*>(func_start), func_size);
  if (ret < 0)
    fprintf(stderr, "WARNING: cannot get prog tag, ignore saving source with program tag\n");
  funcs_[func_name] = fd;
  return StatusTuple::OK();
}

StatusTuple BPF::unload_func(const std::string& func_name) {
  auto it = funcs_.find(func_name);
  if (it == funcs_.end())
    return StatusTuple::OK();

  int res = close(it->second);
  if (res != 0)
    return StatusTuple(-1, "Can't close FD for %s: %d", it->first.c_str(), res);

  funcs_.erase(it);
  return StatusTuple::OK();
}

StatusTuple BPF::attach_func(int prog_fd, int attachable_fd,
                             enum bpf_attach_type attach_type,
                             uint64_t flags) {
  int res = bpf_module_->bcc_func_attach(prog_fd, attachable_fd, attach_type, flags);
  if (res != 0)
    return StatusTuple(-1, "Can't attach for prog_fd %d, attachable_fd %d, "
                           "attach_type %d, flags %ld: error %d",
                       prog_fd, attachable_fd, attach_type, flags, res);

  return StatusTuple::OK();
}

StatusTuple BPF::detach_func(int prog_fd, int attachable_fd,
                             enum bpf_attach_type attach_type) {
  int res = bpf_module_->bcc_func_detach(prog_fd, attachable_fd, attach_type);
  if (res != 0)
    return StatusTuple(-1, "Can't detach for prog_fd %d, attachable_fd %d, "
                           "attach_type %d: error %d",
                       prog_fd, attachable_fd, attach_type, res);

  return StatusTuple::OK();
}

std::string BPF::get_syscall_fnname(const std::string& name) {
  if (syscall_prefix_ == nullptr) {
    KSyms ksym;
    uint64_t addr;

    if (ksym.resolve_name(nullptr, "sys_bpf", &addr))
      syscall_prefix_.reset(new std::string("sys_"));
    else if (ksym.resolve_name(nullptr, "__x64_sys_bpf", &addr))
      syscall_prefix_.reset(new std::string("__x64_sys_"));
    else
      syscall_prefix_.reset(new std::string());
  }

  return *syscall_prefix_ + name;
}

StatusTuple BPF::check_binary_symbol(const std::string& binary_path,
                                     const std::string& symbol,
                                     uint64_t symbol_addr,
                                     std::string& module_res,
                                     uint64_t& offset_res,
                                     uint64_t symbol_offset) {
  bcc_symbol output;
  int res = bcc_resolve_symname(binary_path.c_str(), symbol.c_str(),
                                symbol_addr, -1, nullptr, &output);
  if (res < 0)
    return StatusTuple(
        -1, "Unable to find offset for binary %s symbol %s address %lx",
        binary_path.c_str(), symbol.c_str(), symbol_addr);

  if (output.module) {
    module_res = output.module;
    ::free(const_cast<char*>(output.module));
  } else {
    module_res = "";
  }
  offset_res = output.offset + symbol_offset;
  return StatusTuple::OK();
}

std::string BPF::get_kprobe_event(const std::string& kernel_func,
                                  bpf_probe_attach_type type) {
  std::string res = attach_type_prefix(type) + "_";
  res += sanitize_str(kernel_func, &BPF::kprobe_event_validator);
  return res;
}

BPFProgTable BPF::get_prog_table(const std::string& name) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFProgTable(it->second);
  return BPFProgTable({});
}

BPFCgroupArray BPF::get_cgroup_array(const std::string& name) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFCgroupArray(it->second);
  return BPFCgroupArray({});
}

BPFDevmapTable BPF::get_devmap_table(const std::string& name) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFDevmapTable(it->second);
  return BPFDevmapTable({});
}

BPFXskmapTable BPF::get_xskmap_table(const std::string& name) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFXskmapTable(it->second);
  return BPFXskmapTable({});
}

BPFStackTable BPF::get_stack_table(const std::string& name, bool use_debug_file,
                                   bool check_debug_file_crc) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFStackTable(it->second, use_debug_file, check_debug_file_crc);
  return BPFStackTable({}, use_debug_file, check_debug_file_crc);
}

BPFStackBuildIdTable BPF::get_stackbuildid_table(const std::string &name, bool use_debug_file,
                                                 bool check_debug_file_crc) {
  TableStorage::iterator it;

  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFStackBuildIdTable(it->second, use_debug_file, check_debug_file_crc, get_bsymcache());
  return BPFStackBuildIdTable({}, use_debug_file, check_debug_file_crc, get_bsymcache());
}

BPFMapInMapTable BPF::get_map_in_map_table(const std::string& name) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFMapInMapTable(it->second);
  return BPFMapInMapTable({});
}

BPFSockmapTable BPF::get_sockmap_table(const std::string& name) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFSockmapTable(it->second);
  return BPFSockmapTable({});
}

BPFSockhashTable BPF::get_sockhash_table(const std::string& name) {
  TableStorage::iterator it;
  if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
    return BPFSockhashTable(it->second);
  return BPFSockhashTable({});
}

bool BPF::add_module(std::string module)
{
  return bcc_buildsymcache_add_module(get_bsymcache(), module.c_str()) != 0 ?
    false : true;
}

std::string BPF::get_uprobe_event(const std::string& binary_path,
                                  uint64_t offset, bpf_probe_attach_type type,
                                  pid_t pid) {
  std::string res = attach_type_prefix(type) + "_";
  res += sanitize_str(binary_path, &BPF::uprobe_path_validator);
  res += "_0x" + uint_to_hex(offset);
  if (pid != -1)
    res += "_" + std::to_string(pid);
  return res;
}

StatusTuple BPF::detach_kprobe_event(const std::string& event,
                                     open_probe_t& attr) {
  bpf_close_perf_event_fd(attr.perf_event_fd);
  TRY2(unload_func(attr.func));
  if (bpf_detach_kprobe(event.c_str()) < 0)
    return StatusTuple(-1, "Unable to detach kprobe %s", event.c_str());
  return StatusTuple::OK();
}

StatusTuple BPF::detach_uprobe_event(const std::string& event,
                                     open_probe_t& attr) {
  bpf_close_perf_event_fd(attr.perf_event_fd);
  TRY2(unload_func(attr.func));
  if (bpf_detach_uprobe(event.c_str()) < 0)
    return StatusTuple(-1, "Unable to detach uprobe %s", event.c_str());
  return StatusTuple::OK();
}

StatusTuple BPF::detach_tracepoint_event(const std::string& tracepoint,
                                         open_probe_t& attr) {
  bpf_close_perf_event_fd(attr.perf_event_fd);
  TRY2(unload_func(attr.func));

  // TODO: bpf_detach_tracepoint currently does nothing.
  return StatusTuple::OK();
}

StatusTuple BPF::detach_raw_tracepoint_event(const std::string& tracepoint,
                                             open_probe_t& attr) {
  TRY2(close(attr.perf_event_fd));
  TRY2(unload_func(attr.func));

  return StatusTuple::OK();
}

StatusTuple BPF::detach_perf_event_all_cpu(open_probe_t& attr) {
  bool has_error = false;
  std::string err_msg;
  for (const auto& it : *attr.per_cpu_fd) {
    int res = bpf_close_perf_event_fd(it.second);
    if (res != 0) {
      has_error = true;
      err_msg += "Failed to close perf event FD " + std::to_string(it.second) +
                 " For CPU " + std::to_string(it.first) + ": ";
      err_msg += std::string(std::strerror(errno)) + "\n";
    }
  }
  delete attr.per_cpu_fd;
  TRY2(unload_func(attr.func));

  if (has_error)
    return StatusTuple(-1, err_msg);
  return StatusTuple::OK();
}

int BPF::free_bcc_memory() {
  return bcc_free_memory();
}

USDT::USDT(const std::string& binary_path, const std::string& provider,
           const std::string& name, const std::string& probe_func)
    : initialized_(false),
      binary_path_(binary_path),
      pid_(-1),
      provider_(provider),
      name_(name),
      probe_func_(probe_func),
      mod_match_inode_only_(1) {}

USDT::USDT(pid_t pid, const std::string& provider, const std::string& name,
           const std::string& probe_func)
    : initialized_(false),
      binary_path_(),
      pid_(pid),
      provider_(provider),
      name_(name),
      probe_func_(probe_func),
      mod_match_inode_only_(1) {}

USDT::USDT(const std::string& binary_path, pid_t pid,
           const std::string& provider, const std::string& name,
           const std::string& probe_func)
    : initialized_(false),
      binary_path_(binary_path),
      pid_(pid),
      provider_(provider),
      name_(name),
      probe_func_(probe_func),
      mod_match_inode_only_(1) {}

USDT::USDT(const USDT& usdt)
    : initialized_(false),
      binary_path_(usdt.binary_path_),
      pid_(usdt.pid_),
      provider_(usdt.provider_),
      name_(usdt.name_),
      probe_func_(usdt.probe_func_),
      mod_match_inode_only_(usdt.mod_match_inode_only_) {}

USDT::USDT(USDT&& usdt) noexcept
    : initialized_(usdt.initialized_),
      binary_path_(std::move(usdt.binary_path_)),
      pid_(usdt.pid_),
      provider_(std::move(usdt.provider_)),
      name_(std::move(usdt.name_)),
      probe_func_(std::move(usdt.probe_func_)),
      probe_(std::move(usdt.probe_)),
      program_text_(std::move(usdt.program_text_)),
      mod_match_inode_only_(usdt.mod_match_inode_only_) {
  usdt.initialized_ = false;
}

bool USDT::operator==(const USDT& other) const {
  return (provider_ == other.provider_) && (name_ == other.name_) &&
         (binary_path_ == other.binary_path_) && (pid_ == other.pid_) &&
         (probe_func_ == other.probe_func_);
}

int USDT::set_probe_matching_kludge(uint8_t kludge) {
  if (kludge != 0 && kludge != 1)
    return -1;

  mod_match_inode_only_ = kludge;
  return 0;
}

StatusTuple USDT::init() {
  std::unique_ptr<::USDT::Context> ctx;
  if (!binary_path_.empty() && pid_ > 0)
    ctx.reset(new ::USDT::Context(pid_, binary_path_, mod_match_inode_only_));
  else if (!binary_path_.empty())
    ctx.reset(new ::USDT::Context(binary_path_, mod_match_inode_only_));
  else if (pid_ > 0)
    ctx.reset(new ::USDT::Context(pid_, mod_match_inode_only_));
  else
    return StatusTuple(-1, "No valid Binary Path or PID provided");

  if (!ctx->loaded())
    return StatusTuple(-1, "Unable to load USDT " + print_name());

  auto deleter = [](void* probe) { delete static_cast<::USDT::Probe*>(probe); };
  for (auto& p : ctx->probes_) {
    if (p->provider_ == provider_ && p->name_ == name_) {
      // Take ownership of the probe that we are interested in, and avoid it
      // being destructed when we destruct the USDT::Context instance
      probe_ = std::unique_ptr<void, std::function<void(void*)>>(p.release(),
                                                                 deleter);
      p.swap(ctx->probes_.back());
      ctx->probes_.pop_back();
      break;
    }
  }
  if (!probe_)
    return StatusTuple(-1, "Unable to find USDT " + print_name());
  ctx.reset(nullptr);
  auto& probe = *static_cast<::USDT::Probe*>(probe_.get());

  std::ostringstream stream;
  if (!probe.usdt_getarg(stream, probe_func_))
    return StatusTuple(
        -1, "Unable to generate program text for USDT " + print_name());
  program_text_ = ::USDT::USDT_PROGRAM_HEADER + stream.str();

  initialized_ = true;
  return StatusTuple::OK();
}

}  // namespace ebpf
