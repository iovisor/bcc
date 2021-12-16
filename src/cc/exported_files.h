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

#pragma once

#include <map>
#include <string>

namespace ebpf {

class ExportedFiles {
  static std::map<std::string, const char *> headers_;
  static std::map<std::string, const char *> footers_;
 public:
  static const std::map<std::string, const char *> & headers() { return headers_; }
  static const std::map<std::string, const char *> & footers() { return footers_; }
};

}
