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

#pragma once

#include <cctype>
#include <memory>
#include <string>

#include "BPFTable.h"
#include "bcc_exception.h"
#include "bcc_syms.h"
#include "bpf_module.h"
#include "compat/linux/bpf.h"
#include "libbpf.h"

namespace ebpf {

struct open_probe_t {
  void* reader_ptr;
  std::string func;
  std::map<int, int>* per_cpu_fd;
};

class USDT;

class BPF {
public:
  static const int BPF_MAX_STACK_DEPTH = 127;

  explicit BPF(unsigned int flag = 0) : bpf_module_(new BPFModule(flag)) {}
  StatusTuple init(const std::string& bpf_program,
                   std::vector<std::string> cflags = {},
                   std::vector<USDT> usdt = {});

  ~BPF();
  StatusTuple detach_all();

  StatusTuple attach_kprobe(
      const std::string& kernel_func, const std::string& probe_func,
      bpf_probe_attach_type = BPF_PROBE_ENTRY,
      pid_t pid = -1, int cpu = 0, int group_fd = -1,
      perf_reader_cb cb = nullptr, void* cb_cookie = nullptr);
  StatusTuple detach_kprobe(
      const std::string& kernel_func,
      bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY);

  StatusTuple attach_uprobe(
      const std::string& binary_path, const std::string& symbol,
      const std::string& probe_func, uint64_t symbol_addr = 0,
      bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY,
      pid_t pid = -1, int cpu = 0, int group_fd = -1,
      perf_reader_cb cb = nullptr, void* cb_cookie = nullptr);
  StatusTuple detach_uprobe(
      const std::string& binary_path, const std::string& symbol,
      uint64_t symbol_addr = 0,
      bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY);
  StatusTuple attach_usdt(const USDT& usdt, pid_t pid = -1, int cpu = 0,
                          int group_fd = -1);
  StatusTuple detach_usdt(const USDT& usdt);

  StatusTuple attach_tracepoint(const std::string& tracepoint,
                                const std::string& probe_func,
                                pid_t pid = -1, int cpu = 0, int group_fd = -1,
                                perf_reader_cb cb = nullptr,
                                void* cb_cookie = nullptr);
  StatusTuple detach_tracepoint(const std::string& tracepoint);

  StatusTuple attach_perf_event(uint32_t ev_type, uint32_t ev_config,
                                const std::string& probe_func,
                                uint64_t sample_period, uint64_t sample_freq,
                                pid_t pid = -1, int cpu = -1,
                                int group_fd = -1);
  StatusTuple detach_perf_event(uint32_t ev_type, uint32_t ev_config);

  template <class KeyType, class ValueType>
  BPFHashTable<KeyType, ValueType> get_hash_table(const std::string& name) {
    return BPFHashTable<KeyType, ValueType>(bpf_module_.get(), name);
  }

  BPFStackTable get_stack_table(const std::string& name) {
    return BPFStackTable(bpf_module_.get(), name);
  }

  StatusTuple open_perf_buffer(const std::string& name, perf_reader_raw_cb cb,
                               void* cb_cookie = nullptr);
  StatusTuple close_perf_buffer(const std::string& name);
  void poll_perf_buffer(const std::string& name, int timeout = -1);

  BPFModule* get_module() const {
    return bpf_module_.get();
  }

private:
  StatusTuple load_func(const std::string& func_name, enum bpf_prog_type type,
                        int& fd);
  StatusTuple unload_func(const std::string& func_name);

  std::string get_kprobe_event(const std::string& kernel_func,
                               bpf_probe_attach_type type);
  std::string get_uprobe_event(const std::string& binary_path, uint64_t offset,
                               bpf_probe_attach_type type);

  StatusTuple detach_kprobe_event(const std::string& event, open_probe_t& attr);
  StatusTuple detach_uprobe_event(const std::string& event, open_probe_t& attr);
  StatusTuple detach_tracepoint_event(const std::string& tracepoint,
                                      open_probe_t& attr);
  StatusTuple detach_perf_event_all_cpu(open_probe_t& attr);

  std::string attach_type_debug(bpf_probe_attach_type type) {
    switch (type) {
    case BPF_PROBE_ENTRY:
      return "";
    case BPF_PROBE_RETURN:
      return "return ";
    }
    return "ERROR";
  }

  std::string attach_type_prefix(bpf_probe_attach_type type) {
    switch (type) {
    case BPF_PROBE_ENTRY:
      return "p";
    case BPF_PROBE_RETURN:
      return "r";
    }
    return "ERROR";
  }

  static bool kprobe_event_validator(char c) {
    return (c != '+') && (c != '.');
  }

  static bool uprobe_path_validator(char c) {
    return std::isalpha(c) || std::isdigit(c) || (c == '_');
  }

  StatusTuple check_binary_symbol(const std::string& binary_path,
                                  const std::string& symbol,
                                  uint64_t symbol_addr, bcc_symbol* output);

  std::unique_ptr<BPFModule> bpf_module_;

  std::map<std::string, int> funcs_;

  std::vector<USDT> usdt_;

  std::map<std::string, open_probe_t> kprobes_;
  std::map<std::string, open_probe_t> uprobes_;
  std::map<std::string, open_probe_t> tracepoints_;
  std::map<std::string, BPFPerfBuffer*> perf_buffers_;
  std::map<std::pair<uint32_t, uint32_t>, open_probe_t> perf_events_;
};

class USDT {
public:
  USDT(const std::string& binary_path, const std::string& provider,
       const std::string& name, const std::string& probe_func)
      : initialized_(false),
        binary_path_(binary_path),
        provider_(provider),
        name_(name),
        probe_func_(probe_func) {}

  bool operator==(const USDT& other) const {
    return (provider_ == other.provider_) && (name_ == other.name_) &&
           (binary_path_ == other.binary_path_) &&
           (probe_func_ == other.probe_func_);
  }

  std::string print_name() const {
    return provider_ + ":" + name_ + " from " + binary_path_;
  }

private:
  StatusTuple init();
  bool initialized_;

  std::string binary_path_;
  std::string provider_;
  std::string name_;
  std::string probe_func_;

  std::vector<intptr_t> addresses_;

  std::string program_text_;

  friend class BPF;
};

}  // namespace ebpf
