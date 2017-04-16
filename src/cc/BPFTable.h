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

#include <cstring>
#include <sys/epoll.h>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "bcc_exception.h"
#include "bpf_module.h"
#include "libbpf.h"
#include "perf_reader.h"
#include "table_desc.h"

namespace ebpf {

template <class KeyType, class ValueType>
class BPFTableBase {
 public:
  size_t capacity() { return capacity_; }

 protected:
  explicit BPFTableBase(const TableDesc& desc) {
    fd_ = desc.fd;
    capacity_ = desc.max_entries;
  }

  bool lookup(KeyType* key, ValueType* value) {
    return bpf_lookup_elem(fd_, static_cast<void*>(key),
                           static_cast<void*>(value)) >= 0;
  }

  bool next(KeyType* key, KeyType* next_key) {
    return bpf_get_next_key(fd_, static_cast<void*>(key),
                            static_cast<void*>(next_key)) >= 0;
  }

  bool update(KeyType* key, ValueType* value) {
    return bpf_update_elem(fd_, static_cast<void*>(key),
                           static_cast<void*>(value), 0) >= 0;
  }

  bool remove(KeyType* key) {
    return bpf_delete_elem(fd_, static_cast<void*>(key)) >= 0;
  }

  int fd_;
  size_t capacity_;
};

template <class ValueType>
class BPFArrayTable : protected BPFTableBase<int, ValueType> {
public:
  BPFArrayTable(const TableDesc& desc)
      : BPFTableBase<int, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_ARRAY &&
        desc.type != BPF_MAP_TYPE_PERCPU_ARRAY)
      throw std::invalid_argument("Table '" + desc.name + "' is not an array table");
  }

  StatusTuple get_value(const int& index, ValueType& value) {
    if (!this->lookup(const_cast<int*>(&index), &value))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  StatusTuple update_value(const int& index, const ValueType& value) {
    if (!this->update(const_cast<int*>(&index), const_cast<ValueType*>(&value)))
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

    for (int i = 0; i < (int) this->capacity(); i++) {
      get_value(i, res[i]);
    }

    return res;
  }
};

template <class KeyType, class ValueType>
class BPFHashTable : protected BPFTableBase<KeyType, ValueType> {
 public:
  explicit BPFHashTable(const TableDesc& desc)
      : BPFTableBase<KeyType, ValueType>(desc) {
    if (desc.type != BPF_MAP_TYPE_HASH &&
        desc.type != BPF_MAP_TYPE_PERCPU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_HASH &&
        desc.type != BPF_MAP_TYPE_LRU_PERCPU_HASH)
      throw std::invalid_argument("Table '" + desc.name + "' is not a hash table");
  }

  StatusTuple get_value(const KeyType& key, ValueType& value) {
    if (!this->lookup(const_cast<KeyType*>(&key), &value))
      return StatusTuple(-1, "Error getting value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  StatusTuple update_value(const KeyType& key, const ValueType& value) {
    if (!this->update(const_cast<KeyType*>(&key), const_cast<ValueType*>(&value)))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple(0);
  }

  StatusTuple remove_value(const KeyType& key) {
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

    KeyType cur, nxt;
    ValueType value;

    while (true) {
      if (!this->next(&cur, &nxt))
        break;
      if (!this->lookup(&nxt, &value))
        break;
      res.emplace_back(nxt, value);
      std::swap(cur, nxt);
    }

    return res;
  }
};

// From src/cc/export/helpers.h
static const int BPF_MAX_STACK_DEPTH = 127;
struct stacktrace_t {
  intptr_t ip[BPF_MAX_STACK_DEPTH];
};

class BPFStackTable : protected BPFTableBase<int, stacktrace_t> {
 public:
  BPFStackTable(const TableDesc& desc)
      : BPFTableBase<int, stacktrace_t>(desc) {}
  ~BPFStackTable();

  std::vector<intptr_t> get_stack_addr(int stack_id);
  std::vector<std::string> get_stack_symbol(int stack_id, int pid);

 private:
  std::map<int, void*> pid_sym_;
};

class BPFPerfBuffer : protected BPFTableBase<int, int> {
 public:
  BPFPerfBuffer(const TableDesc& desc)
      : BPFTableBase<int, int>(desc), epfd_(-1) {}
  ~BPFPerfBuffer();

  StatusTuple open_all_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                           void* cb_cookie, int page_cnt);
  StatusTuple close_all_cpu();
  void poll(int timeout);

 private:
  StatusTuple open_on_cpu(perf_reader_raw_cb cb, perf_reader_lost_cb lost_cb,
                          int cpu, void* cb_cookie, int page_cnt);
  StatusTuple close_on_cpu(int cpu);

  std::map<int, perf_reader*> cpu_readers_;

  int epfd_;
  std::unique_ptr<epoll_event[]> ep_events_;
};

class BPFProgTable : protected BPFTableBase<int, int> {
public:
  BPFProgTable(const TableDesc& desc)
      : BPFTableBase<int, int>(desc) {
    if (desc.type != BPF_MAP_TYPE_PROG_ARRAY)
      throw std::invalid_argument("Table '" + desc.name + "' is not a prog table");
  }

  // updates an element
  StatusTuple update_value(const int& index, const int& value) {
    if (!this->update(const_cast<int*>(&index), const_cast<int*>(&value)))
      return StatusTuple(-1, "Error updating value: %s", std::strerror(errno));
    return StatusTuple(0);
  }
};

}  // namespace ebpf
