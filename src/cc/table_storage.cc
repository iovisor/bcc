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

#include <unistd.h>

#include <clang/AST/Type.h>

#include "table_storage_impl.h"

namespace ebpf {

using std::move;
using std::string;
using std::unique_ptr;

const string Path::DELIM = "/";

TableStorage::TableStorage() {}
TableStorage::~TableStorage() {}
void TableStorage::Init(unique_ptr<TableStorageImpl> impl) { impl_ = move(impl); }
bool TableStorage::Find(const Path &path, TableStorage::iterator &result) const {
  return impl_->Find(path.to_string(), result);
}
bool TableStorage::Insert(const Path &path, TableDesc &&desc) {
  return impl_->Insert(path.to_string(), move(desc));
}
bool TableStorage::Delete(const Path &path) { return impl_->Delete(path.to_string()); }
size_t TableStorage::DeletePrefix(const Path &path) {
  size_t i = 0;
  auto it = lower_bound(path);
  auto upper = upper_bound(path);
  while (it != upper) {
    it = impl_->erase(*it.impl_);
    ++i;
  }
  return i;
}

void TableStorage::AddMapTypesVisitor(unique_ptr<MapTypesVisitor> visitor) {
  visitors_.push_back(move(visitor));
}
void TableStorage::VisitMapType(TableDesc &desc, clang::ASTContext &C, clang::QualType key_type,
                                clang::QualType leaf_type) {
  for (auto &v : visitors_)
    v->Visit(desc, C, key_type, leaf_type);
}

TableStorage::iterator TableStorage::begin() { return impl_->begin(); }
TableStorage::iterator TableStorage::end() { return impl_->end(); }
TableStorage::iterator TableStorage::lower_bound(const Path &p) {
  return impl_->lower_bound(p.to_string());
}
TableStorage::iterator TableStorage::upper_bound(const Path &p) {
  return impl_->upper_bound(p.to_string() + "\x7f");
}

/// TableStorage::iterator implementation
TableStorage::iterator::iterator() {}
TableStorage::iterator::iterator(unique_ptr<TableStorageIteratorImpl> impl) : impl_(move(impl)) {}
TableStorage::iterator::iterator(const iterator &that) : impl_(that.impl_->clone()) {}
TableStorage::iterator::~iterator() {}
TableStorage::iterator::iterator(iterator &&that) { *this = move(that); }
TableStorage::iterator &TableStorage::iterator::operator=(iterator &&that) {
  impl_ = move(that.impl_);
  return *this;
}

TableStorage::iterator &TableStorage::iterator::operator++() {
  ++*impl_;
  return *this;
}
TableStorage::iterator TableStorage::iterator::operator++(int) {
  iterator tmp(*this);
  operator++();
  return tmp;
}
bool TableStorage::iterator::operator==(const iterator &rhs) const {
  // assumes that the underlying pair is stored in only one place
  return &**impl_ == &**rhs.impl_;
}
bool TableStorage::iterator::operator!=(const iterator &rhs) const {
  return &**impl_ != &**rhs.impl_;
}
TableStorage::iterator::reference TableStorage::iterator::operator*() const { return **impl_; }
TableStorage::iterator::pointer TableStorage::iterator::operator->() const { return &**impl_; }

}  // namespace ebpf
