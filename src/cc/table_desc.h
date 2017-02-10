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

#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace clang {
class ASTContext;
class QualType;
}

namespace ebpf {

struct TableDesc {
  std::string name;
  int fd;
  int type;
  size_t key_size;  // sizes are in bytes
  size_t leaf_size;
  size_t max_entries;
  int flags;
  std::string key_desc;
  std::string leaf_desc;
  llvm::Function *key_sscanf;
  llvm::Function *leaf_sscanf;
  llvm::Function *key_snprintf;
  llvm::Function *leaf_snprintf;
  bool is_shared;
  bool is_extern;
};

class MapTypesVisitor {
 public:
  virtual ~MapTypesVisitor() {}

  virtual void visit(
      clang::ASTContext& C,
      const std::string& table,
      clang::QualType keyType,
      clang::QualType leafType) = 0;
};

}  // namespace ebpf
