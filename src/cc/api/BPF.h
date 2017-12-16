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
#include <cstdint>
#include <memory>
#include <string>

#include "BPFTable.h"
#include "bcc_exception.h"
#include "bcc_syms.h"
#include "bpf_module.h"
#include "compat/linux/bpf.h"
#include "libbpf.h"
#include "table_storage.h"

static const int DEFAULT_PERF_BUFFER_PAGE_CNT = 8;

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

  explicit BPF(unsigned int flag = 0, TableStorage* ts = nullptr)
      : flag_(flag), bpf_module_(new BPFModule(flag, ts)) {}
  StatusTuple init(const std::string& bpf_program,
                   const std::vector<std::string>& cflags = {},
                   const std::vector<USDT>& usdt = {});

  ~BPF();
  StatusTuple detach_all();

  StatusTuple attach_kprobe(const std::string& kernel_func,
                            const std::string& probe_func,
                            bpf_probe_attach_type = BPF_PROBE_ENTRY,
                            perf_reader_cb cb = nullptr,
                            void* cb_cookie = nullptr);
  StatusTuple detach_kprobe(
      const std::string& kernel_func,
      bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY);

  StatusTuple attach_uprobe(const std::string& binary_path,
                            const std::string& symbol,
                            const std::string& probe_func,
                            uint64_t symbol_addr = 0,
                            bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY,
                            pid_t pid = -1, perf_reader_cb cb = nullptr,
                            void* cb_cookie = nullptr);
  StatusTuple detach_uprobe(const std::string& binary_path,
                            const std::string& symbol, uint64_t symbol_addr = 0,
                            bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY,
                            pid_t pid = -1);
  StatusTuple attach_usdt(const USDT& usdt, pid_t pid = -1);
  StatusTuple detach_usdt(const USDT& usdt);

  StatusTuple attach_tracepoint(const std::string& tracepoint,
                                const std::string& probe_func,
                                perf_reader_cb cb = nullptr,
                                void* cb_cookie = nullptr);
  StatusTuple detach_tracepoint(const std::string& tracepoint);

  StatusTuple attach_perf_event(uint32_t ev_type, uint32_t ev_config,
                                const std::string& probe_func,
                                uint64_t sample_period, uint64_t sample_freq,
                                pid_t pid = -1, int cpu = -1,
                                int group_fd = -1);
  StatusTuple detach_perf_event(uint32_t ev_type, uint32_t ev_config);

  BPFTable get_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFTable(it->second);
    return BPFTable({});
  }

  template <class ValueType>
  BPFArrayTable<ValueType> get_array_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFArrayTable<ValueType>(it->second);
    return BPFArrayTable<ValueType>({});
  }

  template <class KeyType, class ValueType>
  BPFHashTable<KeyType, ValueType> get_hash_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFHashTable<KeyType, ValueType>(it->second);
    return BPFHashTable<KeyType, ValueType>({});
  }

  BPFProgTable get_prog_table(const std::string& name);

  BPFStackTable get_stack_table(const std::string& name,
                                bool use_debug_file = true,
                                bool check_debug_file_crc = true);

  StatusTuple open_perf_event(const std::string& name, uint32_t type,
                              uint64_t config);

  StatusTuple close_perf_event(const std::string& name);

  StatusTuple open_perf_buffer(const std::string& name, perf_reader_raw_cb cb,
                               perf_reader_lost_cb lost_cb = nullptr,
                               void* cb_cookie = nullptr,
                               int page_cnt = DEFAULT_PERF_BUFFER_PAGE_CNT);
  StatusTuple close_perf_buffer(const std::string& name);
  void poll_perf_buffer(const std::string& name, int timeout = -1);

  StatusTuple load_func(const std::string& func_name, enum bpf_prog_type type,
                        int& fd);
  StatusTuple unload_func(const std::string& func_name);

 private:
  std::string get_kprobe_event(const std::string& kernel_func,
                               bpf_probe_attach_type type);
  std::string get_uprobe_event(const std::string& binary_path, uint64_t offset,
                               bpf_probe_attach_type type, pid_t pid);

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
                                  uint64_t symbol_addr, std::string& module_res,
                                  uint64_t& offset_res);

  int flag_;

  std::unique_ptr<BPFModule> bpf_module_;

  std::map<std::string, int> funcs_;

  std::vector<USDT> usdt_;

  std::map<std::string, open_probe_t> kprobes_;
  std::map<std::string, open_probe_t> uprobes_;
  std::map<std::string, open_probe_t> tracepoints_;
  std::map<std::string, BPFPerfBuffer*> perf_buffers_;
  std::map<std::string, BPFPerfEventArray*> perf_event_arrays_;
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

  std::vector<uintptr_t> addresses_;

  std::string program_text_;

  friend class BPF;
};

}  // namespace ebpf
