--[[
Copyright 2016 GitHub, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]
local ffi = require("ffi")

ffi.cdef[[
enum bpf_prog_type {
  BPF_PROG_TYPE_UNSPEC,
  BPF_PROG_TYPE_SOCKET_FILTER,
  BPF_PROG_TYPE_KPROBE,
  BPF_PROG_TYPE_SCHED_CLS,
  BPF_PROG_TYPE_SCHED_ACT,
};

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, int map_flags);
int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags);
int bpf_lookup_elem(int fd, void *key, void *value);
int bpf_delete_elem(int fd, void *key);
int bpf_get_next_key(int fd, void *key, void *next_key);

int bpf_prog_load(enum bpf_prog_type prog_type, const char *name,
  const struct bpf_insn *insns, int insn_len,
  const char *license, unsigned kern_version,
  int log_level, char *log_buf, unsigned log_buf_size);
int bpf_attach_socket(int sockfd, int progfd);

/* create RAW socket and bind to interface 'name' */
int bpf_open_raw_sock(const char *name);

typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);
typedef void (*perf_reader_lost_cb)(void *cb_cookie, uint64_t lost);

int bpf_attach_kprobe(int progfd, int attach_type, const char *ev_name,
                      const char *fn_name);

int bpf_detach_kprobe(const char *ev_name);

int bpf_attach_uprobe(int progfd, int attach_type, const char *ev_name,
                      const char *binary_path, uint64_t offset, int pid);

int bpf_detach_uprobe(const char *ev_name);

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb, perf_reader_lost_cb lost_cb, void *cb_cookie, int pid, int cpu, int page_cnt);

int bpf_close_perf_event_fd(int fd);
]]

ffi.cdef[[
void * bpf_module_create_b(const char *filename, const char *proto_filename, unsigned flags);
void * bpf_module_create_c(const char *filename, unsigned flags, const char *cflags[], int ncflags);
void * bpf_module_create_c_from_string(const char *text, unsigned flags, const char *cflags[], int ncflags);
void bpf_module_destroy(void *program);
char * bpf_module_license(void *program);
unsigned bpf_module_kern_version(void *program);
size_t bpf_num_functions(void *program);
const char * bpf_function_name(void *program, size_t id);
void * bpf_function_start_id(void *program, size_t id);
void * bpf_function_start(void *program, const char *name);
size_t bpf_function_size_id(void *program, size_t id);
size_t bpf_function_size(void *program, const char *name);
size_t bpf_num_tables(void *program);
size_t bpf_table_id(void *program, const char *table_name);
int bpf_table_fd(void *program, const char *table_name);
int bpf_table_fd_id(void *program, size_t id);
int bpf_table_type(void *program, const char *table_name);
int bpf_table_type_id(void *program, size_t id);
size_t bpf_table_max_entries(void *program, const char *table_name);
size_t bpf_table_max_entries_id(void *program, size_t id);
int bpf_table_flags(void *program, const char *table_name);
int bpf_table_flags_id(void *program, size_t id);
const char * bpf_table_name(void *program, size_t id);
const char * bpf_table_key_desc(void *program, const char *table_name);
const char * bpf_table_key_desc_id(void *program, size_t id);
const char * bpf_table_leaf_desc(void *program, const char *table_name);
const char * bpf_table_leaf_desc_id(void *program, size_t id);
size_t bpf_table_key_size(void *program, const char *table_name);
size_t bpf_table_key_size_id(void *program, size_t id);
size_t bpf_table_leaf_size(void *program, const char *table_name);
size_t bpf_table_leaf_size_id(void *program, size_t id);
int bpf_table_key_snprintf(void *program, size_t id, char *buf, size_t buflen, const void *key);
int bpf_table_leaf_snprintf(void *program, size_t id, char *buf, size_t buflen, const void *leaf);
int bpf_table_key_sscanf(void *program, size_t id, const char *buf, void *key);
int bpf_table_leaf_sscanf(void *program, size_t id, const char *buf, void *leaf);
]]

ffi.cdef[[
struct perf_reader;

void perf_reader_free(void *ptr);
int perf_reader_mmap(struct perf_reader *reader);
int perf_reader_poll(int num_readers, struct perf_reader **readers, int timeout);
int perf_reader_fd(struct perf_reader *reader);
void perf_reader_set_fd(struct perf_reader *reader, int fd);
]]

ffi.cdef[[
struct bcc_symbol {
	const char *name;
	const char *demangle_name;
	const char *module;
	uint64_t offset;
};

struct bcc_symbol_option {
  int use_debug_file;
  int check_debug_file_crc;
  uint32_t use_symbol_type;
};

int bcc_resolve_symname(const char *module, const char *symname, const uint64_t addr,
                        int pid, struct bcc_symbol_option *option,
                        struct bcc_symbol *sym);
void bcc_procutils_free(const char *ptr);
void *bcc_symcache_new(int pid, struct bcc_symbol_option *option);
void bcc_symbol_free_demangle_name(struct bcc_symbol *sym);
int bcc_symcache_resolve(void *symcache, uint64_t addr, struct bcc_symbol *sym);
void bcc_symcache_refresh(void *resolver);
]]

ffi.cdef[[
void *bcc_usdt_new_frompid(int pid);
void *bcc_usdt_new_frompath(const char *path);
void bcc_usdt_close(void *usdt);

int bcc_usdt_enable_probe(void *, const char *, const char *);
char *bcc_usdt_genargs(void *);

typedef void (*bcc_usdt_uprobe_cb)(const char *, const char *, uint64_t, int);
void bcc_usdt_foreach_uprobe(void *usdt, bcc_usdt_uprobe_cb callback);
]]

if rawget(_G, "BCC_STANDALONE") then
  return ffi.C
else
  return ffi.load(
    os.getenv("LIBBCC_SO_PATH") or
    rawget(_G, "LIBBCC_SO_PATH") or
    "bcc")
end
