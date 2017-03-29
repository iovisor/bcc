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

#include <cstddef>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "table_desc.h"

namespace ebpf {

class TableStorageImpl;
class TableStorageIteratorImpl;

class Path {
 public:
  static const std::string DELIM;
  Path() = default;
  Path(const Path &other) = default;
  Path &operator=(const Path &other) = default;
  Path(std::initializer_list<std::string> parts) {
    size_t len = parts.size() * DELIM.size();
    for (const auto &s : parts)
      len += s.size();
    path_.reserve(len);
    for (const auto &s : parts)
      path_ += DELIM + s;
  }
  const std::string &to_string() const { return path_; }

 private:
  std::string path_;
};

class TableStorage {
 public:
  /// iterator is an abstract class for traversing the map entries in a table
  /// storage object.
  class iterator {
   private:
    friend class TableStorage;
    iterator(const iterator &);

   public:
    typedef std::pair<const std::string, TableDesc> value_type;
    typedef std::ptrdiff_t difference_type;
    typedef value_type *pointer;
    typedef value_type &reference;
    typedef std::forward_iterator_tag iterator_category;
    typedef iterator self_type;

    iterator();
    iterator(std::unique_ptr<TableStorageIteratorImpl>);
    ~iterator();
    iterator(iterator &&);
    iterator &operator=(iterator &&);
    self_type &operator++();
    self_type operator++(int);
    bool operator==(const self_type &) const;
    bool operator!=(const self_type &) const;
    value_type &operator*() const;
    pointer operator->() const;

   private:
    std::unique_ptr<TableStorageIteratorImpl> impl_;
  };

  TableStorage();
  ~TableStorage();
  void Init(std::unique_ptr<TableStorageImpl>);

  bool Find(const Path &path, TableStorage::iterator &result) const;
  bool Insert(const Path &path, TableDesc &&desc);
  bool Delete(const Path &path);
  size_t DeletePrefix(const Path &path);

  void AddMapTypesVisitor(std::unique_ptr<MapTypesVisitor>);
  void VisitMapType(TableDesc &desc, clang::ASTContext &C, clang::QualType key_type,
                    clang::QualType leaf_type);
  iterator begin();
  iterator end();
  iterator lower_bound(const Path &p);
  iterator upper_bound(const Path &p);

 private:
  std::unique_ptr<TableStorageImpl> impl_;
  std::vector<std::unique_ptr<MapTypesVisitor>> visitors_;
};

std::unique_ptr<TableStorage> createSharedTableStorage();
std::unique_ptr<TableStorage> createBpfFsTableStorage();
}
