/*
 * Copyright (c) 2017 VMware, Inc.
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

#include "common.h"
#include "table_storage_impl.h"

namespace ebpf {

using std::string;
using std::unique_ptr;

/// A filesystem backed table storage
class BpfFsTableStorage : public TableStorageImpl {
 public:
  class iterator : public TableStorageIteratorImpl {
   public:
    virtual ~iterator() {}
    virtual unique_ptr<self_type> clone() const override;
    virtual self_type &operator++() override;
    virtual value_type &operator*() const override;
    virtual pointer operator->() const override;
  };
  virtual ~BpfFsTableStorage() {}
  virtual bool Find(const string &name, TableStorage::iterator &result) const override;
  virtual bool Insert(const string &name, TableDesc &&desc) override;
  virtual bool Delete(const string &name) override;
  virtual unique_ptr<TableStorageIteratorImpl> begin() override;
  virtual unique_ptr<TableStorageIteratorImpl> end() override;
  virtual unique_ptr<TableStorageIteratorImpl> lower_bound(const string &k) override;
  virtual unique_ptr<TableStorageIteratorImpl> upper_bound(const string &k) override;
  virtual unique_ptr<TableStorageIteratorImpl> erase(const TableStorageIteratorImpl &it) override;

 private:
};

bool BpfFsTableStorage::Find(const string &name, TableStorage::iterator &result) const {
  return false;
}

bool BpfFsTableStorage::Insert(const string &name, TableDesc &&desc) { return false; }

bool BpfFsTableStorage::Delete(const string &name) { return false; }

unique_ptr<TableStorageIteratorImpl> BpfFsTableStorage::begin() { return unique_ptr<iterator>(); }
unique_ptr<TableStorageIteratorImpl> BpfFsTableStorage::end() { return unique_ptr<iterator>(); }
unique_ptr<TableStorageIteratorImpl> BpfFsTableStorage::lower_bound(const string &k) {
  return unique_ptr<iterator>();
}
unique_ptr<TableStorageIteratorImpl> BpfFsTableStorage::upper_bound(const string &k) {
  return unique_ptr<iterator>();
}
unique_ptr<TableStorageIteratorImpl> BpfFsTableStorage::erase(const TableStorageIteratorImpl &it) {
  return unique_ptr<iterator>();
}

unique_ptr<TableStorage> createBpfFsTableStorage() {
  auto t = make_unique<TableStorage>();
  t->Init(make_unique<BpfFsTableStorage>());
  return t;
}

}  // namespace ebpf
