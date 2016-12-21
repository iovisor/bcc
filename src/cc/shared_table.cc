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

#include <unistd.h>

#include "shared_table.h"
#include "compat/linux/bpf.h"

namespace ebpf {

using std::string;

SharedTables * SharedTables::instance_;

SharedTables * SharedTables::instance() {
  if (!instance_) {
    instance_ = new SharedTables;
  }
  return instance_;
}

int SharedTables::lookup_fd(const string &name) const {
  auto table = tables_.find(name);
  if (table == tables_.end())
    return -1;
  return table->second.first;
}

int SharedTables::lookup_type(const string &name) const {
  auto table = tables_.find(name);
  if (table == tables_.end())
    return BPF_MAP_TYPE_UNSPEC;
  return table->second.second;
}

bool SharedTables::insert_fd(const string &name, int fd, int type) {
  if (tables_.find(name) != tables_.end())
    return false;
  tables_[name] = std::make_pair(fd, type);
  return true;
}

bool SharedTables::remove_fd(const string &name) {
  auto table = tables_.find(name);
  if (table == tables_.end())
    return false;
  close(table->second.first);
  tables_.erase(table);
  return true;
}

}
