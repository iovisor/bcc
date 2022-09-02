/*
 * Copyright (c) 2016 Catalysts GmbH
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
#include <fstream>
#include <sstream>

#include "common.h"
#include "bcc_libbpf_inc.h"
#include "vendor/optional.hpp"
#include "vendor/tinyformat.hpp"

namespace ebpf {

using std::experimental::optional;

// Get enum value from BTF, since the enum may be anonymous, like:
//   [608] ENUM '(anon)' size=4 vlen=1
//   	'TASK_COMM_LEN' val=16
// we have to traverse the whole BTF.
// Though there is a BTF_KIND_ENUM64, but it is unlikely that it will
// be used as array size, we don't handle it here.
static optional<int32_t> get_enum_val_from_btf(const char *name) {
  optional<int32_t> val;

  auto btf = btf__load_vmlinux_btf();
  if (libbpf_get_error(btf))
    return {};

  for (size_t i = 1; i < btf__type_cnt(btf); i++) {
    auto t = btf__type_by_id(btf, i);
    if (btf_kind(t) != BTF_KIND_ENUM)
      continue;

    auto m = btf_enum(t);
    for (int j = 0, n = btf_vlen(t); j < n; j++, m++) {
      if (!strcmp(btf__name_by_offset(btf, m->name_off), name)) {
        val = m->val;
        break;
      }
    }

    if (val)
      break;
  }

  btf__free(btf);
  return val;
}

std::vector<int> read_cpu_range(std::string path) {
  std::ifstream cpus_range_stream { path };
  std::vector<int> cpus;
  std::string cpu_range;

  while (std::getline(cpus_range_stream, cpu_range, ',')) {
    std::size_t rangeop = cpu_range.find('-');
    if (rangeop == std::string::npos) {
      cpus.push_back(std::stoi(cpu_range));
    }
    else {
      int start = std::stoi(cpu_range.substr(0, rangeop));
      int end = std::stoi(cpu_range.substr(rangeop + 1));
      for (int i = start; i <= end; i++)
        cpus.push_back(i);
    }
  }
  return cpus;
}

std::vector<int> get_online_cpus() {
  return read_cpu_range("/sys/devices/system/cpu/online");
}

std::vector<int> get_possible_cpus() {
  return read_cpu_range("/sys/devices/system/cpu/possible");
}

std::string get_pid_exe(pid_t pid) {
  char exe_path[4096];
  int res;

  std::string exe_link = tfm::format("/proc/%d/exe", pid);
  res = readlink(exe_link.c_str(), exe_path, sizeof(exe_path));
  if (res == -1)
    return "";
  if (res >= static_cast<int>(sizeof(exe_path)))
    res = sizeof(exe_path) - 1;
  exe_path[res] = '\0';
  return std::string(exe_path);
}

enum class field_kind_t {
    common,
    data_loc,
    regular,
    invalid,
    pad,
};

static inline field_kind_t _get_field_kind(std::string const& line,
                                           std::string& field_type,
                                           std::string& field_name,
                                           int *last_offset) {
  auto field_pos = line.find("field:");
  if (field_pos == std::string::npos)
    return field_kind_t::invalid;

  auto field_semi_pos = line.find(';', field_pos);
  if (field_semi_pos == std::string::npos)
    return field_kind_t::invalid;

  auto offset_pos = line.find("offset:", field_semi_pos);
  if (offset_pos == std::string::npos)
    return field_kind_t::invalid;

  auto semi_pos = line.find(';', offset_pos);
  if (semi_pos == std::string::npos)
    return field_kind_t::invalid;

  auto offset_str = line.substr(offset_pos + 7,
                              semi_pos - offset_pos - 7);
  int offset = std::stoi(offset_str, nullptr);

  auto size_pos = line.find("size:", semi_pos);
  if (size_pos == std::string::npos)
    return field_kind_t::invalid;

  semi_pos = line.find(';', size_pos);
  if (semi_pos == std::string::npos)
    return field_kind_t::invalid;

  auto size_str = line.substr(size_pos + 5,
                              semi_pos - size_pos - 5);
  int size = std::stoi(size_str, nullptr);

  if (*last_offset < offset) {
    *last_offset += 1;
    return field_kind_t::pad;
  }

  *last_offset = offset + size;

  auto field = line.substr(field_pos + 6/*"field:"*/,
                           field_semi_pos - field_pos - 6);
  auto pos = field.find_last_of("\t ");
  if (pos == std::string::npos)
    return field_kind_t::invalid;

  field_type = field.substr(0, pos);
  field_name = field.substr(pos + 1);
  if (field_type.find("__data_loc") != std::string::npos)
    return field_kind_t::data_loc;
  if (field_name.find("common_") == 0)
    return field_kind_t::common;

  // We may have `char comm[TASK_COMM_LEN];` on kernel v5.18+
  // Let's replace `TASK_COMM_LEN` with value extracted from BTF
  if (field_name.find("[") != std::string::npos) {
    auto pos1 = field_name.find("[");
    auto pos2 = field_name.find("]");
    auto dim = field_name.substr(pos1 + 1, pos2 - pos1 - 1);
    if (!dim.empty() && !isdigit(dim[0])) {
      auto v = get_enum_val_from_btf(dim.c_str());
      if (v)
        dim = std::to_string(*v);
      field_name.replace(pos1 + 1, pos2 - pos1 - 1, dim, 0);
    }
    return field_kind_t::regular;
  }

  // adjust the field_type based on the size of field
  // otherwise, incorrect value may be retrieved for big endian
  // and the field may have incorrect structure offset.
  if (size == 2) {
    if (field_type == "char" || field_type == "int8_t")
      field_type = "s16";
    if (field_type == "unsigned char" || field_type == "uint8_t")
      field_type = "u16";
  } else if (size == 4) {
    if (field_type == "char" || field_type == "short" ||
        field_type == "int8_t" || field_type == "int16_t")
      field_type = "s32";
    if (field_type == "unsigned char" || field_type == "unsigned short" ||
        field_type == "uint8_t" || field_type == "uint16_t")
      field_type = "u32";
  } else if (size == 8) {
    if (field_type == "char" || field_type == "short" || field_type == "int" ||
        field_type == "int8_t" || field_type == "int16_t" ||
        field_type == "int32_t" || field_type == "pid_t")
      field_type = "s64";
    if (field_type == "unsigned char" || field_type == "unsigned short" ||
        field_type == "unsigned int" || field_type == "uint8_t" ||
        field_type == "uint16_t" || field_type == "uint32_t" ||
        field_type == "unsigned" || field_type == "u32" ||
        field_type == "uid_t" || field_type == "gid_t")
      field_type = "u64";
  }

  return field_kind_t::regular;
}

#define DEBUGFS_TRACEFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

std::string tracefs_path() {
  static bool use_debugfs = access(DEBUGFS_TRACEFS, F_OK) == 0;
  return use_debugfs ? DEBUGFS_TRACEFS : TRACEFS;
}

std::string tracepoint_format_file(std::string const& category,
                                   std::string const& event) {
  return tracefs_path() + "/events/" + category + "/" + event + "/format";
}

std::string parse_tracepoint(std::istream &input, std::string const& category,
                             std::string const& event) {
  std::string tp_struct = "struct tracepoint__" + category + "__" + event + " {\n";
  tp_struct += "\tu64 __do_not_use__;\n";
  int last_offset = 0, common_offset = 8;
  for (std::string line; getline(input, line); ) {
    std::string field_type, field_name;
    field_kind_t kind;

    do {
      kind = _get_field_kind(line, field_type, field_name, &last_offset);

      switch (kind) {
      case field_kind_t::invalid:
          continue;
      case field_kind_t::common:
            for (;common_offset < last_offset; common_offset++)
            {
              tp_struct += "\tchar __do_not_use__" + std::to_string(common_offset) + ";\n";
            }
          continue;
      case field_kind_t::data_loc:
          tp_struct += "\tint data_loc_" + field_name + ";\n";
          break;
      case field_kind_t::regular:
          tp_struct += "\t" + field_type + " " + field_name + ";\n";
          break;
      case field_kind_t::pad:
          tp_struct += "\tchar __pad_" + std::to_string(last_offset - 1) + ";\n";
          break;
      }
    } while (kind == field_kind_t::pad);
  }

  tp_struct += "};\n";
  return tp_struct;
}
} // namespace ebpf
