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

struct TableDesc;

class SharedTables {
 public:
  static SharedTables * instance();
  // add an fd to the shared table, return true if successfully inserted
  bool insert_fd(const std::string &name, int fd);
  // lookup an fd in the shared table, or -1 if not found
  int lookup_fd(const std::string &name) const;
  // close and remove a shared fd. return true if the value was found
  bool remove_fd(const std::string &name);
 private:
  static SharedTables *instance_;
  std::map<std::string, int> tables_;
};

}
