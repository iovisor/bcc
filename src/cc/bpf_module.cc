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
#include "bpf_module.h"

#include "common.h"
#include "libbpf.h"
#include "table_storage.h"
#include "func_source.h"
#include "table_desc.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

namespace ebpf {

using std::get;
using std::string;
using std::unique_ptr;

const string BPFModule::FN_PREFIX = BPF_FN_PREFIX;

void BPFModule::init_module()
{
  if (!ts_) {
    local_ts_ = createSharedTableStorage();
    ts_ = &*local_ts_;
  }
  func_src_ = ebpf::make_unique<FuncSource>();
}

static StatusTuple unimplemented_sscanf(const char *, void *) {
  return StatusTuple(-1, "sscanf unimplemented");
}
static StatusTuple unimplemented_snprintf(char *, size_t, const void *) {
  return StatusTuple(-1, "snprintf unimplemented");
}

void BPFModule::cleanup_module()
{
  for (auto &v : tables_) {
    v->key_sscanf = unimplemented_sscanf;
    v->leaf_sscanf = unimplemented_sscanf;
    v->key_snprintf = unimplemented_snprintf;
    v->leaf_snprintf = unimplemented_snprintf;
  }

  func_src_.reset();

  ts_->DeletePrefix(Path({id_}));
}

size_t BPFModule::num_functions() const {
  return function_names_.size();
}

const char * BPFModule::function_name(size_t id) const {
  if (id >= function_names_.size())
    return nullptr;
  return function_names_[id].c_str() + FN_PREFIX.size();
}

uint8_t * BPFModule::function_start(size_t id) const {
  if (id >= function_names_.size())
    return nullptr;
  auto section = sections_.find(function_names_[id]);
  if (section == sections_.end())
    return nullptr;
  return get<0>(section->second);
}

uint8_t * BPFModule::function_start(const string &name) const {
  auto section = sections_.find(FN_PREFIX + name);
  if (section == sections_.end())
    return nullptr;

  return get<0>(section->second);
}

const char * BPFModule::function_source(const string &name) const {
  return func_src_->src(name);
}

const char * BPFModule::function_source_rewritten(const string &name) const {
  return func_src_->src_rewritten(name);
}

int BPFModule::annotate_prog_tag(const string &name, int prog_fd,
                                 struct bpf_insn *insns, int prog_len) {
  unsigned long long tag1, tag2;
  int err;

  err = bpf_prog_compute_tag(insns, prog_len, &tag1);
  if (err)
    return err;
  err = bpf_prog_get_tag(prog_fd, &tag2);
  if (err)
    return err;
  if (tag1 != tag2) {
    fprintf(stderr, "prog tag mismatch %llx %llx\n", tag1, tag2);
    return -1;
  }

  err = mkdir(BCC_PROG_TAG_DIR, 0777);
  if (err && errno != EEXIST) {
    fprintf(stderr, "cannot create " BCC_PROG_TAG_DIR "\n");
    return -1;
  }

  char buf[128];
  ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx", tag1);
  err = mkdir(buf, 0777);
  if (err && errno != EEXIST) {
    fprintf(stderr, "cannot create %s\n", buf);
    return -1;
  }

  ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx/%s.c",
             tag1, name.data());
  FileDesc fd(open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0644));
  if (fd < 0) {
    fprintf(stderr, "cannot create %s\n", buf);
    return -1;
  }

  const char *src = function_source(name);
  write(fd, src, strlen(src));

  ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx/%s.rewritten.c",
             tag1, name.data());
  fd = open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) {
    fprintf(stderr, "cannot create %s\n", buf);
    return -1;
  }

  src = function_source_rewritten(name);
  write(fd, src, strlen(src));

  if (!src_dbg_fmap_[name].empty()) {
    ::snprintf(buf, sizeof(buf), BCC_PROG_TAG_DIR "/bpf_prog_%llx/%s.dis.txt",
               tag1, name.data());
    fd = open(buf, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
      fprintf(stderr, "cannot create %s\n", buf);
      return -1;
    }

    const char *src = src_dbg_fmap_[name].c_str();
    write(fd, src, strlen(src));
  }

  return 0;
}

size_t BPFModule::function_size(size_t id) const {
  if (id >= function_names_.size())
    return 0;
  auto section = sections_.find(function_names_[id]);
  if (section == sections_.end())
    return 0;
  return get<1>(section->second);
}

size_t BPFModule::function_size(const string &name) const {
  auto section = sections_.find(FN_PREFIX + name);
  if (section == sections_.end())
    return 0;

  return get<1>(section->second);
}

char * BPFModule::license() const {
  auto section = sections_.find("license");
  if (section == sections_.end())
    return nullptr;

  return (char *)get<0>(section->second);
}

unsigned BPFModule::kern_version() const {
  auto section = sections_.find("version");
  if (section == sections_.end())
    return 0;

  return *(unsigned *)get<0>(section->second);
}

size_t BPFModule::num_tables() const { return tables_.size(); }

size_t BPFModule::table_id(const string &name) const {
  auto it = table_names_.find(name);
  if (it == table_names_.end()) return ~0ull;
  return it->second;
}

int BPFModule::table_fd(const string &name) const {
  return table_fd(table_id(name));
}

int BPFModule::table_fd(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->fd;
}

int BPFModule::table_type(const string &name) const {
  return table_type(table_id(name));
}

int BPFModule::table_type(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->type;
}

size_t BPFModule::table_max_entries(const string &name) const {
  return table_max_entries(table_id(name));
}

size_t BPFModule::table_max_entries(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->max_entries;
}

int BPFModule::table_flags(const string &name) const {
  return table_flags(table_id(name));
}

int BPFModule::table_flags(size_t id) const {
  if (id >= tables_.size())
    return -1;
  return tables_[id]->flags;
}

const char * BPFModule::table_name(size_t id) const {
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->name.c_str();
}

const char * BPFModule::table_key_desc(size_t id) const {
  if (used_b_loader_) return nullptr;
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->key_desc.c_str();
}

const char * BPFModule::table_key_desc(const string &name) const {
  return table_key_desc(table_id(name));
}

const char * BPFModule::table_leaf_desc(size_t id) const {
  if (used_b_loader_) return nullptr;
  if (id >= tables_.size())
    return nullptr;
  return tables_[id]->leaf_desc.c_str();
}

const char * BPFModule::table_leaf_desc(const string &name) const {
  return table_leaf_desc(table_id(name));
}
size_t BPFModule::table_key_size(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->key_size;
}
size_t BPFModule::table_key_size(const string &name) const {
  return table_key_size(table_id(name));
}

size_t BPFModule::table_leaf_size(size_t id) const {
  if (id >= tables_.size())
    return 0;
  return tables_[id]->leaf_size;
}
size_t BPFModule::table_leaf_size(const string &name) const {
  return table_leaf_size(table_id(name));
}

struct TableIterator {
  TableIterator(size_t key_size, size_t leaf_size)
      : key(new uint8_t[key_size]), leaf(new uint8_t[leaf_size]) {
  }
  unique_ptr<uint8_t[]> key;
  unique_ptr<uint8_t[]> leaf;
  uint8_t keyb[512];
};

int BPFModule::table_key_printf(size_t id, char *buf, size_t buflen, const void *key) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.key_snprintf(buf, buflen, key);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_printf(size_t id, char *buf, size_t buflen, const void *leaf) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.leaf_snprintf(buf, buflen, leaf);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_key_scanf(size_t id, const char *key_str, void *key) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.key_sscanf(key_str, key);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

int BPFModule::table_leaf_scanf(size_t id, const char *leaf_str, void *leaf) {
  if (id >= tables_.size())
    return -1;
  const TableDesc &desc = *tables_[id];
  StatusTuple rc = desc.leaf_sscanf(leaf_str, leaf);
  if (rc.code() < 0) {
    fprintf(stderr, "%s\n", rc.msg().c_str());
    return -1;
  }
  return 0;
}

} // namespace ebpf
