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
#include <stdarg.h>
#include <string.h>
#include "linux/btf.h"
#include "libbpf.h"
#include "bcc_libbpf_inc.h"
#include <vector>
#include <byteswap.h>

#define BCC_MAX_ERRNO       4095
#define BCC_IS_ERR_VALUE(x) ((x) >= (unsigned long)-BCC_MAX_ERRNO)
#define BCC_IS_ERR(ptr) BCC_IS_ERR_VALUE((unsigned long)ptr)
#ifndef offsetofend
# define offsetofend(TYPE, FIELD) \
	        (offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif

namespace btf_ext_vendored {

/* The minimum bpf_func_info checked by the loader */
struct bpf_func_info_min {
        uint32_t   insn_off;
        uint32_t   type_id;
};

/* The minimum bpf_line_info checked by the loader */
struct bpf_line_info_min {
        uint32_t   insn_off;
        uint32_t   file_name_off;
        uint32_t   line_off;
        uint32_t   line_col;
};

struct btf_ext_sec_setup_param {
        uint32_t off;
        uint32_t len;
        uint32_t min_rec_size;
        struct btf_ext_info *ext_info;
        const char *desc;
};

static int btf_ext_setup_info(struct btf_ext *btf_ext,
                              struct btf_ext_sec_setup_param *ext_sec)
{
        const struct btf_ext_info_sec *sinfo;
        struct btf_ext_info *ext_info;
        uint32_t info_left, record_size;
        /* The start of the info sec (including the __u32 record_size). */
        void *info;

        if (ext_sec->len == 0)
                return 0;

        if (ext_sec->off & 0x03) {
                /*pr_debug(".BTF.ext %s section is not aligned to 4 bytes\n",
                     ext_sec->desc);*/
                return -EINVAL;
        }

        info = (uint8_t*)btf_ext->data + btf_ext->hdr->hdr_len + ext_sec->off;
        info_left = ext_sec->len;

        if ((uint8_t*)btf_ext->data + btf_ext->data_size < (uint8_t*)info + ext_sec->len) {
                /*pr_debug("%s section (off:%u len:%u) is beyond the end of the ELF section .BTF.ext\n",
                         ext_sec->desc, ext_sec->off, ext_sec->len);*/
                return -EINVAL;
        }

        /* At least a record size */
        if (info_left < sizeof(uint32_t)) {
                /*pr_debug(".BTF.ext %s record size not found\n", ext_sec->desc);*/
                return -EINVAL;
        }

        /* The record size needs to meet the minimum standard */
        record_size = *(uint32_t *)info;
        if (record_size < ext_sec->min_rec_size ||
            record_size & 0x03) {
                /*pr_debug("%s section in .BTF.ext has invalid record size %u\n",
                         ext_sec->desc, record_size);*/
                return -EINVAL;
        }

        sinfo = (struct btf_ext_info_sec*)((uint8_t*)info + sizeof(uint32_t));
        info_left -= sizeof(uint32_t);

        /* If no records, return failure now so .BTF.ext won't be used. */
        if (!info_left) {
                /*pr_debug("%s section in .BTF.ext has no records", ext_sec->desc);*/
                return -EINVAL;
        }

        while (info_left) {
                unsigned int sec_hdrlen = sizeof(struct btf_ext_info_sec);
                uint64_t total_record_size;
                uint32_t num_records;

                if (info_left < sec_hdrlen) {
                        /*pr_debug("%s section header is not found in .BTF.ext\n",
                             ext_sec->desc);*/
                        return -EINVAL;
                }

                num_records = sinfo->num_info;
                if (num_records == 0) {
                        /*pr_debug("%s section has incorrect num_records in .BTF.ext\n",
                             ext_sec->desc);*/
                        return -EINVAL;
                }

                total_record_size = sec_hdrlen +
                                    (uint64_t)num_records * record_size;
                if (info_left < total_record_size) {
                        /*pr_debug("%s section has incorrect num_records in .BTF.ext\n",
                             ext_sec->desc);*/
                        return -EINVAL;
                }

                info_left -= total_record_size;
                sinfo = (struct btf_ext_info_sec *)((uint8_t*)sinfo + total_record_size);
        }

        ext_info = ext_sec->ext_info;
        ext_info->len = ext_sec->len - sizeof(uint32_t);
        ext_info->rec_size = record_size;
        ext_info->info = (uint8_t*)info + sizeof(uint32_t);

        return 0;
}

static int btf_ext_setup_func_info(struct btf_ext *btf_ext)
{
        struct btf_ext_sec_setup_param param = {
                .off = btf_ext->hdr->func_info_off,
                .len = btf_ext->hdr->func_info_len,
                .min_rec_size = sizeof(struct bpf_func_info_min),
                .ext_info = &btf_ext->func_info,
                .desc = "func_info"
        };

        return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_line_info(struct btf_ext *btf_ext)
{
        struct btf_ext_sec_setup_param param = {
                .off = btf_ext->hdr->line_info_off,
                .len = btf_ext->hdr->line_info_len,
                .min_rec_size = sizeof(struct bpf_line_info_min),
                .ext_info = &btf_ext->line_info,
                .desc = "line_info",
        };

        return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_setup_core_relos(struct btf_ext *btf_ext)
{
        struct btf_ext_sec_setup_param param = {
                .off = btf_ext->hdr->core_relo_off,
                .len = btf_ext->hdr->core_relo_len,
                .min_rec_size = sizeof(struct bpf_core_relo),
                .ext_info = &btf_ext->core_relo_info,
                .desc = "core_relo",
        };

        return btf_ext_setup_info(btf_ext, &param);
}

static int btf_ext_parse_hdr(uint8_t *data, uint32_t data_size)
{
        const struct btf_ext_header *hdr = (struct btf_ext_header *)data;

        if (data_size < offsetofend(struct btf_ext_header, hdr_len) ||
            data_size < hdr->hdr_len) {
                //pr_debug("BTF.ext header not found");
                return -EINVAL;
        }

        if (hdr->magic == bswap_16(BTF_MAGIC)) {
                //pr_warn("BTF.ext in non-native endianness is not supported\n");
                return -ENOTSUP;
        } else if (hdr->magic != BTF_MAGIC) {
                //pr_debug("Invalid BTF.ext magic:%x\n", hdr->magic);
                return -EINVAL;
        }

        if (hdr->version != BTF_VERSION) {
                //pr_debug("Unsupported BTF.ext version:%u\n", hdr->version);
                return -ENOTSUP;
        }

        if (hdr->flags) {
                //pr_debug("Unsupported BTF.ext flags:%x\n", hdr->flags);
                return -ENOTSUP;
        }

        if (data_size == hdr->hdr_len) {
                //pr_debug("BTF.ext has no data\n");
                return -EINVAL;
        }

        return 0;
}

void btf_ext__free(struct btf_ext *btf_ext)
{
	if((!btf_ext) || BCC_IS_ERR_VALUE((unsigned long)btf_ext))
                return;
        free(btf_ext->data);
        free(btf_ext);
}

struct btf_ext *btf_ext__new(const uint8_t *data, uint32_t size)
{
        struct btf_ext *btf_ext;
        int err;

        btf_ext = (struct btf_ext*)calloc(1, sizeof(struct btf_ext));
        if (!btf_ext)
                return (struct btf_ext*)-ENOMEM;

        btf_ext->data_size = size;
        btf_ext->data = malloc(size);
        if (!btf_ext->data) {
                err = -ENOMEM;
                goto done;
        }
        memcpy(btf_ext->data, data, size);

        err = btf_ext_parse_hdr((uint8_t*)btf_ext->data, size);
        if (err)
                goto done;

        if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, line_info_len)) {
                err = -EINVAL;
                goto done;
        }

        err = btf_ext_setup_func_info(btf_ext);
        if (err)
                goto done;

        err = btf_ext_setup_line_info(btf_ext);
        if (err)
                goto done;

        if (btf_ext->hdr->hdr_len < offsetofend(struct btf_ext_header, core_relo_len)) {
                err = -EINVAL;
                goto done;
        }

        err = btf_ext_setup_core_relos(btf_ext);
        if (err)
                goto done;

done:
        if (err) {
                btf_ext__free(btf_ext);
                return (struct btf_ext*)(uintptr_t)err;
        }

        return btf_ext;
}

static int btf_ext_reloc_info(const struct btf *btf,
                              const struct btf_ext_info *ext_info,
                              const char *sec_name, uint32_t insns_cnt,
                              void **info, uint32_t *cnt)
{
        uint32_t sec_hdrlen = sizeof(struct btf_ext_info_sec);
        uint32_t i, record_size, existing_len, records_len;
        struct btf_ext_info_sec *sinfo;
        const char *info_sec_name;
        uint64_t remain_len;
        void *data;

        record_size = ext_info->rec_size;
        sinfo = (struct btf_ext_info_sec*)ext_info->info;
        remain_len = ext_info->len;
        while (remain_len > 0) {
                records_len = sinfo->num_info * record_size;
                info_sec_name = btf__name_by_offset(btf, sinfo->sec_name_off);
                if (strcmp(info_sec_name, sec_name)) {
                        remain_len -= sec_hdrlen + records_len;
                        sinfo = (struct btf_ext_info_sec*)((uint8_t *)sinfo + sec_hdrlen + records_len);
                        continue;
                }

                existing_len = (*cnt) * record_size;
                data = realloc(*info, existing_len + records_len);
                if (!data)
                        return -ENOMEM;

                memcpy((uint8_t*)data + existing_len, sinfo->data, records_len);
                /* adjust insn_off only, the rest data will be passed
                 * to the kernel.
                 */
                for (i = 0; i < sinfo->num_info; i++) {
                        uint32_t *insn_off;

                        insn_off = (uint32_t *)((uint8_t*)data + existing_len + (i * record_size));
                        *insn_off = *insn_off / sizeof(struct bpf_insn) + insns_cnt;
                }
                *info = data;
                *cnt += sinfo->num_info;
                return 0;
        }

        return -ENOENT;
}

int btf_ext__reloc_func_info(const struct btf *btf,
                             const struct btf_ext *btf_ext,
                             const char *sec_name, uint32_t insns_cnt,
                             void **func_info, uint32_t *cnt)
{
        return btf_ext_vendored::btf_ext_reloc_info(btf, &btf_ext->func_info, sec_name,
                                  insns_cnt, func_info, cnt);
}

int btf_ext__reloc_line_info(const struct btf *btf,
                             const struct btf_ext *btf_ext,
                             const char *sec_name, uint32_t insns_cnt,
                             void **line_info, uint32_t *cnt)
{
        return btf_ext_vendored::btf_ext_reloc_info(btf, &btf_ext->line_info, sec_name,
                                  insns_cnt, line_info, cnt);
}

} // namespace btf_ext_vendored

namespace ebpf {

int32_t BTFStringTable::addString(std::string S) {
  // Check whether the string already exists.
  for (auto &OffsetM : OffsetToIdMap) {
    if (Table[OffsetM.second] == S)
      return OffsetM.first;
  }

  // Make sure we do not overflow the string table.
  if (OrigTblLen + Size + S.size() + 1 >= BTF_MAX_NAME_OFFSET)
    return -1;

  // Not find, add to the string table.
  uint32_t Offset = Size;
  OffsetToIdMap[Offset] = Table.size();
  Table.push_back(S);
  Size += S.size() + 1;
  return Offset;
}

BTF::BTF(bool debug, sec_map_def &sections) : debug_(debug),
    btf_(nullptr), btf_ext_(nullptr), sections_(sections) {
  if (!debug)
    libbpf_set_print(NULL);
}

BTF::~BTF() {
  btf__free(btf_);
  btf_ext__free(btf_ext_);
}

void BTF::warning(const char *format, ...) {
  va_list args;

  if (!debug_)
    return;

  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

void BTF::fixup_btf(uint8_t *type_sec, uintptr_t type_sec_size,
                    char *strings) {
  uint8_t *next_type = type_sec;
  uint8_t *end_type = type_sec + type_sec_size;
  int base_size = sizeof(struct btf_type);

  while (next_type < end_type) {
    struct btf_type *t = (struct btf_type *)next_type;
    unsigned short vlen = BTF_INFO_VLEN(t->info);

    next_type += base_size;

    switch(BTF_INFO_KIND(t->info)) {
    case BTF_KIND_FWD:
    case BTF_KIND_CONST:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_PTR:
    case BTF_KIND_TYPEDEF:
      break;
    case BTF_KIND_FUNC:
      // sanitize vlen to be 0 since bcc does not
      // care about func scope (static, global, extern) yet.
      t->info &= ~0xffff;
      break;
    case BTF_KIND_INT:
      next_type += sizeof(uint32_t);
      break;
    case BTF_KIND_ENUM:
      next_type += vlen * sizeof(struct btf_enum);
      break;
    case BTF_KIND_ARRAY:
      next_type += sizeof(struct btf_array);
      break;
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
      next_type += vlen * sizeof(struct btf_member);
      break;
    case BTF_KIND_FUNC_PROTO:
      next_type += vlen * sizeof(struct btf_param);
      break;
    case BTF_KIND_VAR: {
      // BTF_KIND_VAR is not used by bcc, so
      // a sanitization to convert it to an int.
      // One extra __u32 after btf_type.
      if (sizeof(struct btf_var) == 4) {
        t->name_off = 0;
        t->info = BTF_KIND_INT << 24;
        t->size = 4;

        unsigned *intp = (unsigned *)next_type;
        *intp = BTF_INT_BITS(t->size << 3);
      }

      next_type += sizeof(struct btf_var);
      break;
    }
    case BTF_KIND_DATASEC: {
      // bcc does not use BTF_KIND_DATASEC, so
      // a sanitization here to convert it to a list
      // of void pointers.
      // btf_var_secinfo is 3 __u32's for each var.
      if (sizeof(struct btf_var_secinfo) == 12) {
        t->name_off = 0;
        t->info = BTF_KIND_PTR << 24;
        t->type = 0;

        struct btf_type *typep = (struct btf_type *)next_type;
        for (int i = 0; i < vlen; i++) {
          typep->name_off = 0;
          typep->info = BTF_KIND_PTR << 24;
          typep->type = 0;
          typep++;
        }
      }

      next_type += vlen * sizeof(struct btf_var_secinfo);
      break;
    }
    default:
      // Something not understood
      return;
    }
  }
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

  struct btf_header *hdr = (struct btf_header *)btf_sec;
  struct btf_ext_vendored::btf_ext_header *ehdr = (struct btf_ext_vendored::btf_ext_header *)btf_ext_sec;

  // Fixup btf for old kernels or kernel requirements.
  fixup_btf(btf_sec + hdr->hdr_len + hdr->type_off, hdr->type_len,
            (char *)(btf_sec + hdr->hdr_len + hdr->str_off));

  // Check the LineInfo table and add missing lines
  char *strings = (char *)(btf_sec + hdr->hdr_len + hdr->str_off);
  unsigned orig_strings_len = hdr->str_len;
  unsigned *linfo_s = (unsigned *)(btf_ext_sec + ehdr->hdr_len + ehdr->line_info_off);
  unsigned lrec_size = *linfo_s;
  linfo_s++;
  unsigned linfo_len = ehdr->line_info_len - 4;

  // Go through all line info. For any line number whose line is in the LineCaches,
  // Correct the line_off and record the corresponding source line in BTFStringTable,
  // which later will be merged into .BTF string section.
  BTFStringTable new_strings(orig_strings_len);
  bool overflow = false;
  while (!overflow && linfo_len) {
    unsigned num_recs = linfo_s[1];
    linfo_s += 2;
    for (unsigned i = 0; !overflow && i < num_recs; i++) {
      struct bpf_line_info *linfo = (struct bpf_line_info *)linfo_s;
      if (linfo->line_off == 0) {
        for (auto it = LineCaches.begin(); it != LineCaches.end(); ++it) {
          if (strcmp(strings + linfo->file_name_off, it->first.c_str()) == 0) {
            unsigned line_num = BPF_LINE_INFO_LINE_NUM(linfo->line_col);
            if (line_num > 0 && line_num <= it->second.size()) {
               int offset = new_strings.addString(it->second[line_num - 1]);
               if (offset < 0) {
                 overflow = true;
                 warning(".BTF string table overflowed, some lines missing\n");
                 break;
               }
               linfo->line_off = orig_strings_len + offset;
            }
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
  struct btf_ext_vendored::btf_ext *btf_ext;
  uint8_t *new_btf_sec = NULL;
  uintptr_t new_btf_sec_size = 0;

  adjust(btf_sec, btf_sec_size, btf_ext_sec, btf_ext_sec_size,
         remapped_sources, &new_btf_sec, &new_btf_sec_size);

  if (new_btf_sec) {
    btf = btf__new(new_btf_sec, new_btf_sec_size);
    delete[] new_btf_sec;
  } else {
    btf = btf__new(btf_sec, btf_sec_size);
  }
  if (BCC_IS_ERR(btf)) {
    warning("Processing .BTF section failed\n");
    return -1;
  }

  if (btf__load_into_kernel(btf)) {
    btf__free(btf);
    warning("Loading .BTF section failed\n");
    return -1;
  }

  btf_ext = btf_ext_vendored::btf_ext__new(btf_ext_sec, btf_ext_sec_size);
  if (BCC_IS_ERR(btf_ext)) {
    btf__free(btf);
    warning("Processing .BTF.ext section failed\n");
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

  *finfo_rec_size = btf_ext_->func_info.rec_size;
  *linfo_rec_size = btf_ext_->line_info.rec_size;

  ret = btf_ext_vendored::btf_ext__reloc_func_info(btf_, btf_ext_, fname, 0,
        func_info, func_info_cnt);
  if (ret) {
    warning(".BTF.ext reloc func_info failed\n");
    return ret;
  }

  ret = btf_ext_vendored::btf_ext__reloc_line_info(btf_, btf_ext_, fname, 0,
        line_info, line_info_cnt);
  if (ret) {
    warning(".BTF.ext reloc line_info failed\n");
    return ret;
  }

  return 0;
}

int BTF::get_map_tids(std::string map_name,
                      unsigned expected_ksize, unsigned expected_vsize,
                      unsigned *key_tid, unsigned *value_tid) {
  auto struct_name = "____btf_map_" + map_name;
  auto type_id = btf__find_by_name_kind(btf_, struct_name.c_str(), BTF_KIND_STRUCT);
  if (type_id < 0) {
    warning("struct %s not found in BTF\n", struct_name.c_str());
    return -1;
  }

  auto struct_type = btf__type_by_id(btf_, type_id);
  if (!struct_type || btf_vlen(struct_type) < 2) {
    warning("struct %s is not a valid map struct\n", struct_name.c_str());
    return -1;
  }

  auto members = btf_members(struct_type);
  auto key = members[0];
  auto key_name = btf__name_by_offset(btf_, key.name_off);
  if (strcmp(key_name, "key")) {
    warning("'key' should be the first member\n");
    return -1;
  }
  auto key_size = btf__resolve_size(btf_, key.type);
  if (key_size != expected_ksize) {
    warning("expect key size to be %d, got %d\n", expected_ksize, key_size);
    return -1;
  }
  *key_tid = key.type;

  auto value = members[1];
  auto value_name = btf__name_by_offset(btf_, value.name_off);
  if (strcmp(value_name, "value")) {
    warning("'value' should be the second member\n");
    return -1;
  }
  auto value_size = btf__resolve_size(btf_, value.type);
  if (value_size != expected_vsize) {
    warning("expect value size to be %d, got %d\n", expected_vsize, value_size);
    return -1;
  }
  *value_tid = value.type;

  return 0;
}

} // namespace ebpf
