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

#pragma once

#include "table_storage.h"

namespace ebpf {

class TableStorageIteratorImpl {
 public:
  typedef std::pair<const std::string, TableDesc> value_type;
  typedef value_type *pointer;
  typedef value_type &reference;
  typedef TableStorageIteratorImpl self_type;
  virtual ~TableStorageIteratorImpl() {}
  virtual std::unique_ptr<self_type> clone() const = 0;
  virtual self_type &operator++() = 0;
  virtual value_type &operator*() const = 0;
  virtual pointer operator->() const = 0;

 private:
};

class TableStorageImpl {
 public:
  virtual ~TableStorageImpl(){};
  virtual bool Find(const std::string &name, TableStorage::iterator &result) const = 0;
  virtual bool Insert(const std::string &name, TableDesc &&desc) = 0;
  virtual bool Delete(const std::string &name) = 0;
  virtual std::unique_ptr<TableStorageIteratorImpl> begin() = 0;
  virtual std::unique_ptr<TableStorageIteratorImpl> end() = 0;
  virtual std::unique_ptr<TableStorageIteratorImpl> lower_bound(const std::string &k) = 0;
  virtual std::unique_ptr<TableStorageIteratorImpl> upper_bound(const std::string &k) = 0;
  virtual std::unique_ptr<TableStorageIteratorImpl> erase(const TableStorageIteratorImpl &it) = 0;
};

}  // namespace ebpf
