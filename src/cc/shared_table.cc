/*
 * Copyright (c) 2016 PLUMgrid, Inc.
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

#include <unistd.h>
#include <iostream>

#include "common.h"
#include "compat/linux/bpf.h"
#include "table_storage.h"
#include "table_storage_impl.h"

namespace ebpf {

using std::string;
using std::unique_ptr;

/// A process-wide singleton of shared tables
class SharedTableStorage : public TableStorageImpl {
 public:
  class iterator : public TableStorageIteratorImpl {
    std::map<string, TableDesc>::iterator it_;

   public:
    explicit iterator(const std::map<string, TableDesc>::iterator &it) : it_(it) {}
    virtual ~iterator() {}
    virtual unique_ptr<self_type> clone() const override { return make_unique<iterator>(it_); }
    virtual self_type &operator++() override {
      ++it_;
      return *this;
    }
    virtual value_type &operator*() const override { return *it_; }
    virtual pointer operator->() const override { return &*it_; }
  };
  virtual ~SharedTableStorage() {}
  virtual bool Find(const string &name, TableStorage::iterator &result) const override;
  virtual bool Insert(const string &name, TableDesc &&desc) override;
  virtual bool Delete(const string &name) override;
  virtual unique_ptr<TableStorageIteratorImpl> begin() override;
  virtual unique_ptr<TableStorageIteratorImpl> end() override;
  virtual unique_ptr<TableStorageIteratorImpl> lower_bound(const string &k) override;
  virtual unique_ptr<TableStorageIteratorImpl> upper_bound(const string &k) override;
  virtual unique_ptr<TableStorageIteratorImpl> erase(const TableStorageIteratorImpl &it) override;

 private:
  static std::map<string, TableDesc> tables_;
};

bool SharedTableStorage::Find(const string &name, TableStorage::iterator &result) const {
  auto it = tables_.find(name);
  if (it == tables_.end())
    return false;
  result = TableStorage::iterator(make_unique<iterator>(it));
  return true;
}

bool SharedTableStorage::Insert(const string &name, TableDesc &&desc) {
  auto it = tables_.find(name);
  if (it != tables_.end())
    return false;
  tables_[name] = std::move(desc);
  return true;
}

bool SharedTableStorage::Delete(const string &name) {
  auto it = tables_.find(name);
  if (it == tables_.end())
    return false;
  tables_.erase(it);
  return true;
}

unique_ptr<TableStorageIteratorImpl> SharedTableStorage::begin() {
  return make_unique<iterator>(tables_.begin());
}
unique_ptr<TableStorageIteratorImpl> SharedTableStorage::end() {
  return make_unique<iterator>(tables_.end());
}

unique_ptr<TableStorageIteratorImpl> SharedTableStorage::lower_bound(const string &k) {
  return make_unique<iterator>(tables_.lower_bound(k));
}
unique_ptr<TableStorageIteratorImpl> SharedTableStorage::upper_bound(const string &k) {
  return make_unique<iterator>(tables_.upper_bound(k));
}
unique_ptr<TableStorageIteratorImpl> SharedTableStorage::erase(const TableStorageIteratorImpl &it) {
  auto i = tables_.find((*it).first);
  if (i == tables_.end())
    return unique_ptr<iterator>();
  return make_unique<iterator>(tables_.erase(i));
}

// All maps for this process are kept in global static storage.
std::map<string, TableDesc> SharedTableStorage::tables_;

unique_ptr<TableStorage> createSharedTableStorage() {
  auto t = make_unique<TableStorage>();
  t->Init(make_unique<SharedTableStorage>());
  t->AddMapTypesVisitor(createJsonMapTypesVisitor());
  return t;
}
}
