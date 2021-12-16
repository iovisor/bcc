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

#include "table_storage.h"

namespace llvm {
class Module;
}

namespace ebpf {

namespace cc {
class Parser;
class CodegenLLVM;
}

class BLoader {
 public:
  explicit BLoader(unsigned flags);
  ~BLoader();
  int parse(llvm::Module *mod, const std::string &filename, const std::string &proto_filename,
            TableStorage &ts, const std::string &id, const std::string &maps_ns);

 private:
  unsigned flags_;
  std::unique_ptr<cc::Parser> parser_;
  std::unique_ptr<cc::Parser> proto_parser_;
  std::unique_ptr<cc::CodegenLLVM> codegen_;
};

}  // namespace ebpf
