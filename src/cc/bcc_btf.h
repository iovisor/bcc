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

#include "bpf_module.h"

struct btf;
struct btf_ext;

namespace ebpf {

class BTFStringTable {
 private:
  uint32_t Size;
  uint32_t OrigTblLen;
  std::map<uint32_t, uint32_t> OffsetToIdMap;
  std::vector<std::string> Table;

 public:
  BTFStringTable(uint32_t TblLen): Size(0), OrigTblLen(TblLen) {}
  uint32_t getSize() { return Size; }
  std::vector<std::string> &getTable() { return Table; }
  int32_t addString(std::string Str);
};

class BTF {
  struct bcc_btf_ext_header {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t hdr_len;

    /* All offsets are in bytes relative to the end of this header */
    uint32_t func_info_off;
    uint32_t func_info_len;
    uint32_t line_info_off;
    uint32_t line_info_len;

    /* optional part of .BTF.ext header */
    uint32_t core_relo_off;
    uint32_t core_relo_len;
};

 public:
  BTF(bool debug, sec_map_def &sections);
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
  void fixup_btf(uint8_t *type_sec, uintptr_t type_sec_size, char *strings);
  void adjust(uint8_t *btf_sec, uintptr_t btf_sec_size,
              uint8_t *btf_ext_sec, uintptr_t btf_ext_sec_size,
              std::map<std::string, std::string> &remapped_sources,
              uint8_t **new_btf_sec, uintptr_t *new_btf_sec_size);
  void warning(const char *format, ...);

 private:
  bool debug_;
  struct btf *btf_;
  struct btf_ext *btf_ext_;
  sec_map_def &sections_;
};

} // namespace ebpf

#endif
