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

#include <errno.h>
#include <sys/epoll.h>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "bcc_exception.h"
#include "bcc_syms.h"
#include "bpf_module.h"
#include "libbpf.h"
#include "perf_reader.h"
#include "table_desc.h"

namespace ebpf {

template <class KeyType, class ValueType>
class BPFTableBase {
 public:
  size_t capacity() { return desc.max_entries; }

  StatusTuple string_to_key(const std::string& key_str, KeyType* key) {
    return desc.key_sscanf(key_str.c_str(), key);
  }

  StatusTuple string_to_leaf(const std::string& value_str, ValueType* value) {
    return desc.leaf_sscanf(value_str.c_str(), value);
  }

  StatusTuple key_to_string(const KeyType* key, std::string& key_str) {
    char buf[8 * desc.key_size];
    StatusTuple rc = desc.key_snprintf(buf, sizeof(buf), key);
    if (!rc.code())
      key_str.assign(buf);
    return rc;
  }

  StatusTuple leaf_to_string(const ValueType* value, std::string& value_str) {
    char buf[8 * desc.leaf_size];
    StatusTuple rc = desc.leaf_snprintf(buf, sizeof(buf), value);
    if (!rc.code())
      value_str.assign(buf);
    return rc;
  }

 protected:
  explicit BPFTableBase(const TableDesc& desc) : desc(desc) {}

  bool lookup(void* key, void* value) {
    return bpf_lookup_elem(desc.fd, key, value) >= 0;
  }

  bool first(void* key) {
    return bpf_get_first_key(desc.fd, key, desc.key_size) >= 0;
  }

  bool next(void* key, void* next_key) {
    return bpf_get_next_key(desc.fd, key, next_key) >= 0;
  }

  bool update(void* key, void* value) {
    return bpf_update_elem(desc.fd, key, value, 0) >= 0;
  }

  bool remove(void* key) { return bpf_delete_elem(desc.fd, key) >= 0; }

  const TableDesc& desc;
};

class BPFTable : public BPFTableBase<void, void> {
 public:
  BPFTable(const TableDesc& desc);

  StatusTuple get_value(const std::string& key_str, std::string& value);
  StatusTuple get_value(const std::string& key_str,
                        std::vector<std::string>& value);

  StatusTuple update_value(const std::string& key_str,
                           const std::string& value_str);
  StatusTuple update_value(const std::string& key_str,
                           const std::vector<std::string>& value_str);

  StatusTuple remove_value(const std::string& key_str);

  StatusTuple clear_table_non_atomic();
  StatusTuple get_table_offline(std::vector<std::pair<std::string, std::string>> &res);

  static size_t get_possible_cpu_count();
};

template <class ValueType>
void* get_value_addr(ValueType& t) {
  return &t;
}

template <class ValueType>
void* get_value_addr(std::vector<ValueType>& t) {
  return t.data();
}

template <class ValueType>
class BPFArrayTable : public BPFTableBase<int, ValueType> {
 public:
  BPFArrayTable(const TableDesc& desc) : BPFTableBase<int, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_ARRAY &&
        desc.type != BPF_MAP_TYPE_PERCPU_ARRAY)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not an array table");
  }

  virtual StatusTuple get_value(const int& index, ValueType& value) {
    if (!this->lookup(const_cast<int*>(&index), get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  virtual StatusTuple update_value(const int& index, const ValueType& value) {
    if (!this->update(const_cast<int*>(&index),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  ValueType operator[](const int& key) {
    ValueType value;
    get_value(key, value);
    return value;
  }

  std::vector<ValueType> get_table_offline() {
    std::vector<ValueType> res(this->capacity());

    for (int i = 0; i < (int)this->capacity(); i++) {
      get_value(i, res[i]);
    }

    return res;
  }
};

template <class ValueType>
class BPFPercpuArrayTable : public BPFArrayTable<std::vector<ValueType>> {
 public:
  BPFPercpuArrayTable(const TableDesc& desc)
      : BPFArrayTable<std::vector<ValueType>>(desc),
        ncpus(BPFTable::get_possible_cpu_count()) {
    if (desc.type != BPF_MAP_TYPE_PERCPU_ARRAY)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a percpu array table");
    // leaf structures have to be aligned to 8 bytes as hardcoded in the linux
    // kernel.
    if (sizeof(ValueType) % 8)
      throw std::invalid_argument("leaf must be aligned to 8 bytes");
  }

  StatusTuple get_value(const int& index, std::vector<ValueType>& value) {
    value.resize(ncpus);
    return BPFArrayTable<std::vector<ValueType>>::get_value(index, value);
  }

  StatusTuple update_value(const int& index,
                           const std::vector<ValueType>& value) {
    if (value.size() != ncpus)
      return StatusTuple(-1, "bad value size");
    return BPFArrayTable<std::vector<ValueType>>::update_value(index, value);
  }

 private:
  unsigned int ncpus;
};

template <class KeyType, class ValueType>
class BPFHashTable : public BPFTableBase<KeyType, ValueType> {
 public:
  explicit BPFHashTable(const TableDesc& desc)
      : BPFTableBase<KeyType, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_HASH &&
        desc.type != BPF_MAP_TYPE_PERCPU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_PERCPU_HASH)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a hash table");
  }

  virtual StatusTuple get_value(const KeyType& key, ValueType& value) {
    if (!this->lookup(const_cast<KeyType*>(&key), get_value_addr(value)))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  virtual StatusTuple update_value(const KeyType& key, const ValueType& value) {
    if (!this->update(const_cast<KeyType*>(&key),
                      get_value_addr(const_cast<ValueType&>(value))))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  virtual StatusTuple remove_value(const KeyType& key) {
    if (!this->remove(const_cast<KeyType*>(&key)))
      return StatusTuple(-1, "Error removing value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  ValueType operator[](const KeyType& key) {
    ValueType value;
    get_value(key, value);
    return value;
  }

  std::vector<std::pair<KeyType, ValueType>> get_table_offline() {
    std::vector<std::pair<KeyType, ValueType>> res;
    KeyType cur;
    ValueType value;

    StatusTuple r(0);

    if (!this->first(&cur))
      return res;

    while (true) {
      r = get_value(cur, value);
      if (r.code() != 0)
        break;
      res.emplace_back(cur, value);
      if (!this->next(&cur, &cur))
        break;
    }

    return res;
  }

  StatusTuple clear_table_non_atomic() {
    KeyType cur;
    while (this->first(&cur))
      TRY2(remove_value(cur));

    return StatusTuple(0);
  }
};

template <class KeyType, class ValueType>
class BPFPercpuHashTable
    : public BPFHashTable<KeyType, std::vector<ValueType>> {
 public:
  explicit BPFPercpuHashTable(const TableDesc& desc)
      : BPFHashTable<KeyType, std::vector<ValueType>>(desc),
        ncpus(BPFTable::get_possible_cpu_count()) {
    if (desc.type != BPF_MAP_TYPE_PERCPU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_PERCPU_HASH)
      throw std::invalid_argument("Table '" + desc.name +
                                  "' is not a percpu hash table");
    // leaf structures have to be aligned to 8 bytes as hardcoded in the linux
    // kernel.
    if (sizeof(ValueType) % 8)
      throw std::invalid_argument("leaf must be aligned to 8 bytes");
  }

  StatusTuple get_value(const KeyType& key, std::vector<ValueType>& value) {
    value.resize(ncpus);
    return BPFHashTable<KeyType, std::vector<ValueType>>::get_value(key, value);
  }

  StatusTuple update_value(const KeyType& key,
                           const std::vector<ValueType>& value) {
    if (value.size() != ncpus)
      return StatusTuple(-1, "bad value size");
    return BPFHashTable<KeyType, std::vector<ValueType>>::update_value(key,
                                                                       value);
  }

 private:
  unsigned int ncpus;
};

// From src/cc/export/helpers.h
static const int BPF_MAX_STACK_DEPTH = 127;
struct stacktrace_t {
  uintptr_t ip[BPF_MAX_STACK_DEPTH];
};

class BPFStackTable : public BPFTableBase<int, stacktrace_t> {
 public:
  BPFStackTable(const TableDesc& desc, bool use_debug_file,
                bool check_debug_file_crc);
  BPFStackTable(BPFStackTable&& that);
  ~BPFStackTable();

  void clear_table_non_atomic();
  std::vector<uintptr_t> get_stack_addr(int stack_id);
  std::vector<std::string> get_stack_symbol(int stack_id, int pid);

 private:
  bcc_symbol_option symbol_option_;
  std::map<int, void*> pid_sym_;
};

class BPFPerfBuffer : public BPFTableBase<int, int> {
 public:
  BPFPerfBuffer(const TableDesc& desc);
  ~BPFPerfBuffer();

  StatusTuple open_all_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                           void* cb_cookie, int page_cnt);
  StatusTuple close_all_cpu();
  int poll(int timeout_ms);

 private:
  StatusTuple open_on_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                          int cpu, void* cb_cookie, int page_cnt);
  StatusTuple close_on_cpu(int cpu);

  std::map<int, perf_reader*> cpu_readers_;

  int epfd_;
  std::unique_ptr<epoll_event[]> ep_events_;
};

class BPFPerfEventArray : public BPFTableBase<int, int> {
 public:
  BPFPerfEventArray(const TableDesc& desc);
  ~BPFPerfEventArray();

  StatusTuple open_all_cpu(uint32_t type, uint64_t config);
  StatusTuple close_all_cpu();

 private:
  StatusTuple open_on_cpu(int cpu, uint32_t type, uint64_t config);
  StatusTuple close_on_cpu(int cpu);

  std::map<int, int> cpu_fds_;
};

class BPFProgTable : public BPFTableBase<int, int> {
 public:
  BPFProgTable(const TableDesc& desc);

  StatusTuple update_value(const int& index, const int& prog_fd);
  StatusTuple remove_value(const int& index);
};

class BPFCgroupArray : public BPFTableBase<int, int> {
 public:
  BPFCgroupArray(const TableDesc& desc);

  StatusTuple update_value(const int& index, const int& cgroup2_fd);
  StatusTuple update_value(const int& index, const std::string& cgroup2_path);
  StatusTuple remove_value(const int& index);
};

class BPFDevmapTable : public BPFTableBase<int, int> {
public:
  BPFDevmapTable(const TableDesc& desc);
  
  StatusTuple update_value(const int& index, const int& value);
  StatusTuple get_value(const int& index, int& value);
  StatusTuple remove_value(const int& index);

};

}  // namespace ebpf
