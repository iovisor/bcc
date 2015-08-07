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

#include <map>
#include <memory>
#include <string>

namespace llvm {
class Module;
class LLVMContext;
}

namespace ebpf {

class TableDesc;

namespace cc {
class Parser;
class CodegenLLVM;
}

class ClangLoader {
 public:
  explicit ClangLoader(llvm::LLVMContext *ctx);
  ~ClangLoader();
  int parse(std::unique_ptr<llvm::Module> *mod,
            std::unique_ptr<std::map<std::string, TableDesc>> *tables,
            const std::string &file, bool in_memory);
 private:
  llvm::LLVMContext *ctx_;
};

}  // namespace ebpf
