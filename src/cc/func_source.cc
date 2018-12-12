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

#include "func_source.h"

namespace ebpf {

const char * FuncSource::src(const std::string& name) {
  auto src = funcs_.find(name);
  if (src == funcs_.end())
    return "";
  return src->second.src_.data();
}

const char * FuncSource::src_rewritten(const std::string& name) {
  auto src = funcs_.find(name);
  if (src == funcs_.end())
    return "";
  return src->second.src_rewritten_.data();
}

void FuncSource::set_src(const std::string& name, const std::string& src) {
  funcs_[name].src_ = src;
}

void FuncSource::set_src_rewritten(const std::string& name, const std::string& src) {
  funcs_[name].src_rewritten_ = src;
}

}  // namespace ebpf
