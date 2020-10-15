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
#include <ostream>
#include <string>

#include "BPFTable.h"
#include "bcc_exception.h"
#include "bcc_syms.h"
#include "bpf_module.h"
#include "linux/bpf.h"
#include "libbpf.h"
#include "table_storage.h"

static const int DEFAULT_PERF_BUFFER_PAGE_CNT = 8;

namespace ebpf {

struct open_probe_t {
  int perf_event_fd;
  std::string func;
  std::vector<std::pair<int, int>>* per_cpu_fd;
};

class USDT;

class BPF {
 public:
  static const int BPF_MAX_STACK_DEPTH = 127;

  explicit BPF(unsigned int flag = 0, TableStorage* ts = nullptr,
               bool rw_engine_enabled = bpf_module_rw_engine_enabled(),
               const std::string &maps_ns = "",
               bool allow_rlimit = true)
      : flag_(flag),
        bsymcache_(NULL),
        bpf_module_(new BPFModule(flag, ts, rw_engine_enabled, maps_ns,
                    allow_rlimit)) {}
  StatusTuple init(const std::string& bpf_program,
                   const std::vector<std::string>& cflags = {},
                   const std::vector<USDT>& usdt = {});

  StatusTuple init_usdt(const USDT& usdt);

  ~BPF();
  StatusTuple detach_all();

  StatusTuple attach_kprobe(const std::string& kernel_func,
                            const std::string& probe_func,
                            uint64_t kernel_func_offset = 0,
                            bpf_probe_attach_type = BPF_PROBE_ENTRY,
                            int maxactive = 0);
  StatusTuple detach_kprobe(
      const std::string& kernel_func,
      bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY);

  StatusTuple attach_uprobe(const std::string& binary_path,
                            const std::string& symbol,
                            const std::string& probe_func,
                            uint64_t symbol_addr = 0,
                            bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY,
                            pid_t pid = -1,
                            uint64_t symbol_offset = 0,
                            uint32_t ref_ctr_offset = 0);
  StatusTuple detach_uprobe(const std::string& binary_path,
                            const std::string& symbol, uint64_t symbol_addr = 0,
                            bpf_probe_attach_type attach_type = BPF_PROBE_ENTRY,
                            pid_t pid = -1,
                            uint64_t symbol_offset = 0);
  StatusTuple attach_usdt(const USDT& usdt, pid_t pid = -1);
  StatusTuple attach_usdt_all();
  StatusTuple detach_usdt(const USDT& usdt, pid_t pid = -1);
  StatusTuple detach_usdt_all();

  StatusTuple attach_tracepoint(const std::string& tracepoint,
                                const std::string& probe_func);
  StatusTuple detach_tracepoint(const std::string& tracepoint);

  StatusTuple attach_raw_tracepoint(const std::string& tracepoint,
                                    const std::string& probe_func);
  StatusTuple detach_raw_tracepoint(const std::string& tracepoint);

  StatusTuple attach_perf_event(uint32_t ev_type, uint32_t ev_config,
                                const std::string& probe_func,
                                uint64_t sample_period, uint64_t sample_freq,
                                pid_t pid = -1, int cpu = -1,
                                int group_fd = -1);
  StatusTuple attach_perf_event_raw(void* perf_event_attr,
                                    const std::string& probe_func,
                                    pid_t pid = -1, int cpu = -1,
                                    int group_fd = -1,
                                    unsigned long extra_flags = 0);
  StatusTuple detach_perf_event(uint32_t ev_type, uint32_t ev_config);
  StatusTuple detach_perf_event_raw(void* perf_event_attr);
  std::string get_syscall_fnname(const std::string& name);

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

  template <class ValueType>
  BPFPercpuArrayTable<ValueType> get_percpu_array_table(
      const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFPercpuArrayTable<ValueType>(it->second);
    return BPFPercpuArrayTable<ValueType>({});
  }

  template <class KeyType, class ValueType>
  BPFHashTable<KeyType, ValueType> get_hash_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFHashTable<KeyType, ValueType>(it->second);
    return BPFHashTable<KeyType, ValueType>({});
  }

  template <class KeyType, class ValueType>
  BPFPercpuHashTable<KeyType, ValueType> get_percpu_hash_table(
      const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFPercpuHashTable<KeyType, ValueType>(it->second);
    return BPFPercpuHashTable<KeyType, ValueType>({});
  }

  template <class ValueType>
  BPFSkStorageTable<ValueType> get_sk_storage_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFSkStorageTable<ValueType>(it->second);
    return BPFSkStorageTable<ValueType>({});
  }

  template <class ValueType>
  BPFCgStorageTable<ValueType> get_cg_storage_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFCgStorageTable<ValueType>(it->second);
    return BPFCgStorageTable<ValueType>({});
  }

  template <class ValueType>
  BPFPercpuCgStorageTable<ValueType> get_percpu_cg_storage_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFPercpuCgStorageTable<ValueType>(it->second);
    return BPFPercpuCgStorageTable<ValueType>({});
  }

  template <class ValueType>
  BPFQueueStackTable<ValueType> get_queuestack_table(const std::string& name) {
    TableStorage::iterator it;
    if (bpf_module_->table_storage().Find(Path({bpf_module_->id(), name}), it))
      return BPFQueueStackTable<ValueType>(it->second);
    return BPFQueueStackTable<ValueType>({});
  }

  void* get_bsymcache(void) {
    if (bsymcache_ == NULL) {
      bsymcache_ = bcc_buildsymcache_new();
    }
    return bsymcache_;
  }

  BPFProgTable get_prog_table(const std::string& name);

  BPFCgroupArray get_cgroup_array(const std::string& name);

  BPFDevmapTable get_devmap_table(const std::string& name);

  BPFXskmapTable get_xskmap_table(const std::string& name);

  BPFSockmapTable get_sockmap_table(const std::string& name);

  BPFSockhashTable get_sockhash_table(const std::string& name);

  BPFStackTable get_stack_table(const std::string& name,
                                bool use_debug_file = true,
                                bool check_debug_file_crc = true);

  BPFStackBuildIdTable get_stackbuildid_table(const std::string &name,
                                              bool use_debug_file = true,
                                              bool check_debug_file_crc = true);

  BPFMapInMapTable get_map_in_map_table(const std::string& name);

  bool add_module(std::string module);

  StatusTuple open_perf_event(const std::string& name, uint32_t type,
                              uint64_t config);

  StatusTuple close_perf_event(const std::string& name);

  // Open a Perf Buffer of given name, providing callback and callback cookie
  // to use when polling. BPF class owns the opened Perf Buffer and will free
  // it on-demand or on destruction.
  StatusTuple open_perf_buffer(const std::string& name, perf_reader_raw_cb cb,
                               perf_reader_lost_cb lost_cb = nullptr,
                               void* cb_cookie = nullptr,
                               int page_cnt = DEFAULT_PERF_BUFFER_PAGE_CNT);
  // Close and free the Perf Buffer of given name.
  StatusTuple close_perf_buffer(const std::string& name);
  // Obtain an pointer to the opened BPFPerfBuffer instance of given name.
  // Will return nullptr if such open Perf Buffer doesn't exist.
  BPFPerfBuffer* get_perf_buffer(const std::string& name);
  // Poll an opened Perf Buffer of given name with given timeout, using callback
  // provided when opening. Do nothing if such open Perf Buffer doesn't exist.
  // Returns:
  //   -1 on error or if perf buffer with such name doesn't exist;
  //   0, if no data was available before timeout;
  //   number of CPUs that have new data, otherwise.
  int poll_perf_buffer(const std::string& name, int timeout_ms = -1);

  StatusTuple load_func(const std::string& func_name, enum bpf_prog_type type,
                        int& fd);
  StatusTuple unload_func(const std::string& func_name);

  StatusTuple attach_func(int prog_fd, int attachable_fd,
                          enum bpf_attach_type attach_type,
                          uint64_t flags);
  StatusTuple detach_func(int prog_fd, int attachable_fd,
                          enum bpf_attach_type attach_type);

  int free_bcc_memory();

 private:
  std::string get_kprobe_event(const std::string& kernel_func,
                               bpf_probe_attach_type type);
  std::string get_uprobe_event(const std::string& binary_path, uint64_t offset,
                               bpf_probe_attach_type type, pid_t pid);

  StatusTuple attach_usdt_without_validation(const USDT& usdt, pid_t pid);
  StatusTuple detach_usdt_without_validation(const USDT& usdt, pid_t pid);

  StatusTuple detach_kprobe_event(const std::string& event, open_probe_t& attr);
  StatusTuple detach_uprobe_event(const std::string& event, open_probe_t& attr);
  StatusTuple detach_tracepoint_event(const std::string& tracepoint,
                                      open_probe_t& attr);
  StatusTuple detach_raw_tracepoint_event(const std::string& tracepoint,
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
                                  uint64_t& offset_res,
                                  uint64_t symbol_offset = 0);

  void init_fail_reset();

  int flag_;

  void *bsymcache_;

  std::unique_ptr<std::string> syscall_prefix_;

  std::unique_ptr<BPFModule> bpf_module_;

  std::map<std::string, int> funcs_;

  std::vector<USDT> usdt_;
  std::string all_bpf_program_;

  std::map<std::string, open_probe_t> kprobes_;
  std::map<std::string, open_probe_t> uprobes_;
  std::map<std::string, open_probe_t> tracepoints_;
  std::map<std::string, open_probe_t> raw_tracepoints_;
  std::map<std::string, BPFPerfBuffer*> perf_buffers_;
  std::map<std::string, BPFPerfEventArray*> perf_event_arrays_;
  std::map<std::pair<uint32_t, uint32_t>, open_probe_t> perf_events_;
};

class USDT {
 public:
  USDT(const std::string& binary_path, const std::string& provider,
       const std::string& name, const std::string& probe_func);
  USDT(pid_t pid, const std::string& provider, const std::string& name,
       const std::string& probe_func);
  USDT(const std::string& binary_path, pid_t pid, const std::string& provider,
       const std::string& name, const std::string& probe_func);
  USDT(const USDT& usdt);
  USDT(USDT&& usdt) noexcept;

  const std::string &binary_path() const { return binary_path_; }
  pid_t pid() const { return pid_; }
  const std::string &provider() const { return provider_; }
  const std::string &name() const { return name_; }
  const std::string &probe_func() const { return probe_func_; }

  StatusTuple init();

  bool operator==(const USDT& other) const;

  std::string print_name() const {
    return provider_ + ":" + name_ + " from binary " + binary_path_ + " PID " +
           std::to_string(pid_) + " for probe " + probe_func_;
  }

  friend std::ostream& operator<<(std::ostream& out, const USDT& usdt) {
    return out << usdt.provider_ << ":" << usdt.name_ << " from binary "
               << usdt.binary_path_ << " PID " << usdt.pid_ << " for probe "
               << usdt.probe_func_;
  }

  // When the kludge flag is set to 1 (default), we will only match on inode
  // when searching for modules in /proc/PID/maps that might contain the
  // tracepoint we're looking for.
  // By setting this to 0, we will match on both inode and
  // (dev_major, dev_minor), which is a more accurate way to uniquely
  // identify a file, but may fail depending on the filesystem backing the
  // target file (see bcc#2715)
  //
  // This hack exists because btrfs and overlayfs report different device
  // numbers for files in /proc/PID/maps vs stat syscall. Don't use it unless
  // you've had issues with inode collisions. Both btrfs and overlayfs are
  // known to require inode-only resolution to accurately match a file.
  //
  // set_probe_matching_kludge(0) must be called before USDTs are submitted to
  // BPF::init()
  int set_probe_matching_kludge(uint8_t kludge);

 private:
  bool initialized_;

  std::string binary_path_;
  pid_t pid_;

  std::string provider_;
  std::string name_;
  std::string probe_func_;

  std::unique_ptr<void, std::function<void(void*)>> probe_;
  std::string program_text_;

  uint8_t mod_match_inode_only_;

  friend class BPF;
};

}  // namespace ebpf
