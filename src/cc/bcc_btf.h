/*
 * Copyright (c) 2019 Facebook, Inc.
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

#ifndef BCC_BTF_H
#define BCC_BTF_H

#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <map>
#include <vector>

struct btf;
struct btf_ext;

namespace ebpf {

class BTFStringTable {
 private:
  uint32_t Size;
  std::map<uint32_t, uint32_t> OffsetToIdMap;
  std::vector<std::string> Table;

 public:
  BTFStringTable(): Size(0) {}
  uint32_t getSize() { return Size; }
  std::vector<std::string> &getTable() { return Table; }
  uint32_t addString(std::string Str);
};

class BTF {
 public:
  ~BTF();
  int load(uint8_t *btf_sec, uintptr_t btf_sec_size,
           uint8_t *btf_ext_sec, uintptr_t btf_ext_sec_size,
           std::map<std::string, std::string> &remapped_sources);
  int get_fd();
  int get_btf_info(const char *fname,
                   void **func_info, unsigned *func_info_cnt,
                   unsigned *finfo_rec_size,
                   void **line_info, unsigned *line_info_cnt,
                   unsigned *linfo_rec_size);
  int get_map_tids(std::string map_name,
                   unsigned expected_ksize, unsigned expected_vsize,
                   unsigned *key_tid, unsigned *value_tid);

 private:
  void adjust(uint8_t *btf_sec, uintptr_t btf_sec_size,
              uint8_t *btf_ext_sec, uintptr_t btf_ext_sec_size,
              std::map<std::string, std::string> &remapped_sources,
              uint8_t **new_btf_sec, uintptr_t *new_btf_sec_size);

 private:
  struct btf *btf_;
  struct btf_ext *btf_ext_;
};

} // namespace ebpf

#endif
