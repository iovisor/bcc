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

namespace ebpf {

template <class KeyType, class ValueType>
class BPFTableBase {
public:
  size_t capacity() { return capacity_; }

protected:
  BPFTableBase(BPFModule* bpf_module, const std::string& name) {
    size_t id_ = bpf_module->table_id(name);
    if (id_ >= bpf_module->num_tables())
      throw std::invalid_argument("Table " + name + " does not exist");
    fd_ = bpf_module->table_fd(id_);
    capacity_ = bpf_module->table_max_entries(id_);
  };

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

template <class KeyType, class ValueType>
class BPFHashTable : protected BPFTableBase<KeyType, ValueType> {
public:
  BPFHashTable(BPFModule* bpf_module, const std::string& name)
      : BPFTableBase<KeyType, ValueType>(bpf_module, name) {}

  ValueType get_value(const KeyType& key) {
    ValueType res;
    if (!this->lookup(const_cast<KeyType*>(&key), &res))
      throw std::invalid_argument("Key does not exist in the table");
    return res;
  }

  ValueType operator[](const KeyType& key) { return get_value(key); }

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
  BPFStackTable(BPFModule* bpf_module, const std::string& name)
      : BPFTableBase<int, stacktrace_t>(bpf_module, name) {}
  ~BPFStackTable();

  std::vector<intptr_t> get_stack_addr(int stack_id);
  std::vector<std::string> get_stack_symbol(int stack_id, int pid);

private:
  std::map<int, void*> pid_sym_;
};

class BPFPerfBuffer : protected BPFTableBase<int, int> {
public:
  BPFPerfBuffer(BPFModule* bpf_module, const std::string& name)
      : BPFTableBase<int, int>(bpf_module, name) {}
  ~BPFPerfBuffer();

  StatusTuple open_all_cpu(perf_reader_raw_cb cb, void* cb_cookie);
  StatusTuple close_all_cpu();
  void poll(int timeout);

private:
  StatusTuple open_on_cpu(perf_reader_raw_cb cb, int cpu, void* cb_cookie);
  StatusTuple close_on_cpu(int cpu);

  std::map<int, perf_reader*> cpu_readers_;
  std::vector<perf_reader*> readers_;
};

}  // namespace ebpf
