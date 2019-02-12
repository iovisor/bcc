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

#include "bcc_btf.h"
#include <string.h>
#include "linux/btf.h"
#include "libbpf.h"
#include "libbpf/src/btf.h"
#include <vector>

#define BCC_MAX_ERRNO       4095
#define BCC_IS_ERR_VALUE(x) ((x) >= (unsigned long)-BCC_MAX_ERRNO)
#define BCC_IS_ERR(ptr) BCC_IS_ERR_VALUE((unsigned long)ptr)

namespace ebpf {

uint32_t BTFStringTable::addString(std::string S) {
  // Check whether the string already exists.
  for (auto &OffsetM : OffsetToIdMap) {
    if (Table[OffsetM.second] == S)
      return OffsetM.first;
  }
  // Not find, add to the string table.
  uint32_t Offset = Size;
  OffsetToIdMap[Offset] = Table.size();
  Table.push_back(S);
  Size += S.size() + 1;
  return Offset;
}

BTF::~BTF() {
  btf__free(btf_);
  btf_ext__free(btf_ext_);
}

// The compiler doesn't have source code for remapped files.
// So we modify .BTF and .BTF.ext sections here to add these
// missing line source codes.
// The .BTF and .BTF.ext ELF section specification can be
// found at linux repo: linux/Documentation/bpf/btf.rst.
void BTF::adjust(uint8_t *btf_sec, uintptr_t btf_sec_size,
                 uint8_t *btf_ext_sec, uintptr_t btf_ext_sec_size,
                 std::map<std::string, std::string> &remapped_sources,
                 uint8_t **new_btf_sec, uintptr_t *new_btf_sec_size) {

  // Line cache for remapped files
  std::map<std::string, std::vector<std::string>> LineCaches;
  for (auto it = remapped_sources.begin(); it != remapped_sources.end(); ++it) {
    size_t FileBufSize = it->second.size();
    std::vector<std::string> LineCache;

    for (uint32_t start = 0, end = start; end < FileBufSize; end++) {
      if (it->second[end] == '\n' || end == FileBufSize - 1 ||
          (it->second[end] == '\r' && it->second[end + 1] == '\n')) {
        // Not including the endline
        LineCache.push_back(std::string(it->second.substr(start, end - start)));
        if (it->second[end] == '\r')
          end++;
        start = end + 1;
      }
    }
    LineCaches[it->first] = std::move(LineCache);
  }

  // Check the LineInfo table and add missing lines

  struct btf_header *hdr = (struct btf_header *)btf_sec;
  struct btf_ext_header *ehdr = (struct btf_ext_header *)btf_ext_sec;

  char *strings = (char *)(btf_sec + hdr->hdr_len + hdr->str_off);
  unsigned orig_strings_len = hdr->str_len;
  unsigned *linfo_s = (unsigned *)(btf_ext_sec + ehdr->hdr_len + ehdr->line_info_off);
  unsigned lrec_size = *linfo_s;
  linfo_s++;
  unsigned linfo_len = ehdr->line_info_len - 4;

  // Go through all line info. For any line number whose line is in the LineCaches,
  // Correct the line_off and record the corresponding source line in BTFStringTable,
  // which later will be merged into .BTF string section.
  BTFStringTable new_strings;
  while (linfo_len) {
    unsigned num_recs = linfo_s[1];
    linfo_s += 2;
    for (unsigned i = 0; i < num_recs; i++) {
      struct bpf_line_info *linfo = (struct bpf_line_info *)linfo_s;
      if (linfo->line_off == 0) {
        for (auto it = LineCaches.begin(); it != LineCaches.end(); ++it) {
          if (strcmp(strings + linfo->file_name_off, it->first.c_str()) == 0) {
            unsigned line_num = BPF_LINE_INFO_LINE_NUM(linfo->line_col);
            if (line_num > 0 && line_num <= it->second.size())
               linfo->line_off = orig_strings_len + new_strings.addString(it->second[line_num - 1]);
          }
        }
      }
      linfo_s += lrec_size >> 2;
    }
    linfo_len -= 8 + num_recs * lrec_size;
  }

  // If any new source lines need to be recorded, do not touch the original section,
  // allocate a new section. The original section is allocated through llvm infra.
  if (new_strings.getSize() > 0) {
    // LLVM generated .BTF layout always has type_sec followed by str_sec without holes,
    // so we can just append the new strings to the end and adjust str_sec size.
    unsigned tmp_sec_size = btf_sec_size + new_strings.getSize();
    uint8_t *tmp_sec = new uint8_t[tmp_sec_size];
    memcpy(tmp_sec, btf_sec, btf_sec_size);

    struct btf_header *nhdr = (struct btf_header *)tmp_sec;
    nhdr->str_len += new_strings.getSize();

    // Populate new strings to the string table.
    uint8_t *new_str = tmp_sec + nhdr->hdr_len + nhdr->str_off + orig_strings_len;
    std::vector<std::string> &Table = new_strings.getTable();
    for (unsigned i = 0; i < Table.size(); i++) {
      strcpy((char *)new_str, Table[i].c_str());
      new_str += Table[i].size() + 1;
    }

    *new_btf_sec = tmp_sec;
    *new_btf_sec_size = tmp_sec_size;
  }
}

int BTF::load(uint8_t *btf_sec, uintptr_t btf_sec_size,
              uint8_t *btf_ext_sec, uintptr_t btf_ext_sec_size,
              std::map<std::string, std::string> &remapped_sources) {
  struct btf *btf;
  struct btf_ext *btf_ext;
  uint8_t *new_btf_sec = NULL;
  uintptr_t new_btf_sec_size = 0;

  adjust(btf_sec, btf_sec_size, btf_ext_sec, btf_ext_sec_size,
         remapped_sources, &new_btf_sec, &new_btf_sec_size);

  if (new_btf_sec) {
    btf = btf__new(new_btf_sec, new_btf_sec_size);
    delete new_btf_sec;
  } else {
    btf = btf__new(btf_sec, btf_sec_size);
  }
  if (BCC_IS_ERR(btf)) {
    fprintf(stderr, "Processing .BTF section failure\n");
    return -1;
  }

  btf_ext = btf_ext__new(btf_ext_sec, btf_ext_sec_size);
  if (BCC_IS_ERR(btf_ext)) {
    btf__free(btf);
    fprintf(stderr, "Processing .BTF.ext section failure\n");
    return -1;
  }

  btf_ = btf;
  btf_ext_ = btf_ext;
  return 0;
}

int BTF::get_fd() {
  return btf__fd(btf_);
}

int BTF::get_btf_info(const char *fname,
                      void **func_info, unsigned *func_info_cnt,
                      unsigned *finfo_rec_size,
                      void **line_info, unsigned *line_info_cnt,
                      unsigned *linfo_rec_size) {
  int ret;

  *func_info = *line_info = NULL;
  *func_info_cnt = *line_info_cnt = 0;

  *finfo_rec_size = btf_ext__func_info_rec_size(btf_ext_);
  *linfo_rec_size = btf_ext__line_info_rec_size(btf_ext_);

  ret = btf_ext__reloc_func_info(btf_, btf_ext_, fname, 0,
        func_info, func_info_cnt);
  if (ret) {
    fprintf(stderr, ".BTF.ext reloc func_info not successful\n");
    return ret;
  }

  ret = btf_ext__reloc_line_info(btf_, btf_ext_, fname, 0,
        line_info, line_info_cnt);
  if (ret) {
    fprintf(stderr, ".BTF.ext reloc line_info not successful\n");
    return ret;
  }

  return 0;
}

int BTF::get_map_tids(std::string map_name,
                      unsigned expected_ksize, unsigned expected_vsize,
                      unsigned *key_tid, unsigned *value_tid) {
  return btf__get_map_kv_tids(btf_, map_name.c_str(),
                              expected_ksize, expected_vsize,
                              key_tid, value_tid);
}

} // namespace ebpf
