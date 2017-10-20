/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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

#include <unistd.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "bcc_exception.h"
#include "file_desc.h"

namespace clang {
class ASTContext;
class QualType;
}

namespace ebpf {

typedef std::function<StatusTuple(const char *, void *)> sscanf_fn;
typedef std::function<StatusTuple(char *, size_t, const void *)> snprintf_fn;

/// TableDesc uniquely stores all of the runtime state for an active bpf table.
/// The copy constructor/assign operator are disabled since the file handles
/// owned by this table are not implicitly copyable. One should call the dup()
/// method if an explicit new handle is required. We define the move operators
/// so that objects of this class can reside in stl containers.
class TableDesc {
 private:
  TableDesc(const TableDesc &that)
      : name(that.name),
        fd(that.fd.dup()),
        type(that.type),
        key_size(that.key_size),
        leaf_size(that.leaf_size),
        max_entries(that.max_entries),
        flags(that.flags),
        key_desc(that.key_desc),
        leaf_desc(that.leaf_desc),
        key_sscanf(that.key_sscanf),
        leaf_sscanf(that.leaf_sscanf),
        key_snprintf(that.key_snprintf),
        leaf_snprintf(that.leaf_snprintf),
        is_shared(that.is_shared),
        is_extern(that.is_extern) {}

 public:
  TableDesc()
      : type(0),
        key_size(0),
        leaf_size(0),
        max_entries(0),
        flags(0),
        is_shared(false),
        is_extern(false) {}
  TableDesc(const std::string &name, FileDesc &&fd, int type, size_t key_size,
            size_t leaf_size, size_t max_entries, int flags)
      : name(name),
        fd(std::move(fd)),
        type(type),
        key_size(key_size),
        leaf_size(leaf_size),
        max_entries(max_entries),
        flags(flags),
        is_shared(false),
        is_extern(false) {}
  TableDesc(TableDesc &&that) = default;

  TableDesc &operator=(TableDesc &&that) = default;
  TableDesc &operator=(const TableDesc &that) = delete;

  TableDesc dup() const { return TableDesc(*this); }

  std::string name;
  FileDesc fd;
  int type;
  size_t key_size;  // sizes are in bytes
  size_t leaf_size;
  size_t max_entries;
  int flags;
  std::string key_desc;
  std::string leaf_desc;
  sscanf_fn key_sscanf;
  sscanf_fn leaf_sscanf;
  snprintf_fn key_snprintf;
  snprintf_fn leaf_snprintf;
  bool is_shared;
  bool is_extern;
};

/// MapTypesVisitor gets notified of new bpf tables, and has a chance to parse
/// the key and leaf types for their own usage. Subclass this abstract class and
/// implement the Visit method, then add an instance of this class to the
/// StorageTable instance to be notified of each new key/leaf type.
class MapTypesVisitor {
 public:
  virtual ~MapTypesVisitor() {}
  virtual void Visit(TableDesc &desc, clang::ASTContext &C, clang::QualType key_type,
                     clang::QualType leaf_type) = 0;
};

std::unique_ptr<MapTypesVisitor> createJsonMapTypesVisitor();

}  // namespace ebpf
