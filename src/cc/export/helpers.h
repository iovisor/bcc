R"********(
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
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

/* Before bpf_helpers.h is included, uapi bpf.h has been
 * included, which references linux/types.h. This may bring
 * in asm_volatile_goto definition if permitted based on
 * compiler setup and kernel configs.
 *
 * clang does not support "asm volatile goto" yet.
 * So redefine asm_volatile_goto to some invalid asm code.
 * If asm_volatile_goto is actually used by the bpf program,
 * a compilation error will appear.
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

/* In 4.18 and later, when CONFIG_FUNCTION_TRACER is defined, kernel Makefile adds
 * -DCC_USING_FENTRY. Let do the same for bpf programs.
 */
#if defined(CONFIG_FUNCTION_TRACER)
#define CC_USING_FENTRY
#endif

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_packet.h>
#include <linux/version.h>
#include <linux/log2.h>
#include <asm/page.h>

#ifndef CONFIG_BPF_SYSCALL
#error "CONFIG_BPF_SYSCALL is undefined, please check your .config or ask your Linux distro to enable this feature"
#endif

#ifdef PERF_MAX_STACK_DEPTH
#define BPF_MAX_STACK_DEPTH PERF_MAX_STACK_DEPTH
#else
#define BPF_MAX_STACK_DEPTH 127
#endif

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define BCC_SEC(NAME) __attribute__((section(NAME), used))

// Associate map with its key/value types
#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)	\
        struct ____btf_map_##name {			\
                type_key key;				\
                type_val value;				\
        };						\
        struct ____btf_map_##name			\
        __attribute__ ((section(".maps." #name), used))	\
                ____btf_map_##name = { }

// Associate map with its key/value types for QUEUE/STACK map types
#define BPF_ANNOTATE_KV_PAIR_QUEUESTACK(name, type_val)  \
        struct ____btf_map_##name {     \
                type_val value;       \
        };            \
        struct ____btf_map_##name     \
        __attribute__ ((section(".maps." #name), used)) \
                ____btf_map_##name = { }

// Changes to the macro require changes in BFrontendAction classes
#define BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, _flags) \
struct _name##_table_t { \
  _key_type key; \
  _leaf_type leaf; \
  _leaf_type * (*lookup) (_key_type *); \
  _leaf_type * (*lookup_or_init) (_key_type *, _leaf_type *); \
  _leaf_type * (*lookup_or_try_init) (_key_type *, _leaf_type *); \
  int (*update) (_key_type *, _leaf_type *); \
  int (*insert) (_key_type *, _leaf_type *); \
  int (*delete) (_key_type *); \
  void (*call) (void *, int index); \
  void (*increment) (_key_type, ...); \
  int (*get_stackid) (void *, u64); \
  u32 max_entries; \
  int flags; \
}; \
__attribute__((section("maps/" _table_type))) \
struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR(_name, _key_type, _leaf_type)


// Changes to the macro require changes in BFrontendAction classes
#define BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags) \
struct _name##_table_t { \
  _leaf_type leaf; \
  int * (*peek) (_leaf_type *); \
  int * (*pop) (_leaf_type *); \
  int * (*push) (_leaf_type *, u64); \
  u32 max_entries; \
  int flags; \
}; \
__attribute__((section("maps/" _table_type))) \
struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR_QUEUESTACK(_name, _leaf_type)

// define queue with 3 parameters (_type=queue/stack automatically) and default flags to 0
#define BPF_QUEUE_STACK3(_type, _name, _leaf_type, _max_entries) \
  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, 0)

// define queue with 4 parameters (_type=queue/stack automatically)
#define BPF_QUEUE_STACK4(_type, _name, _leaf_type, _max_entries, _flags) \
  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, _flags)

// helper for default-variable macro function
#define BPF_QUEUE_STACKX(_1, _2, _3, _4, NAME, ...) NAME

#define BPF_QUEUE(...) \
  BPF_QUEUE_STACKX(__VA_ARGS__, BPF_QUEUE_STACK4, BPF_QUEUE_STACK3)("queue", __VA_ARGS__)

#define BPF_STACK(...) \
  BPF_QUEUE_STACKX(__VA_ARGS__, BPF_QUEUE_STACK4, BPF_QUEUE_STACK3)("stack", __VA_ARGS__)

#define BPF_QUEUESTACK_PINNED(_table_type, _name, _leaf_type, _max_entries, _flags, _pinned) \
BPF_QUEUESTACK(_table_type ":" _pinned, _name, _leaf_type, _max_entries, _flags)

#define BPF_QUEUESTACK_PUBLIC(_table_type, _name, _leaf_type, _max_entries, _flags) \
BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags); \
__attribute__((section("maps/export"))) \
struct _name##_table_t __##_name

#define BPF_QUEUESTACK_SHARED(_table_type, _name, _leaf_type, _max_entries, _flags) \
BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags); \
__attribute__((section("maps/shared"))) \
struct _name##_table_t __##_name

#define BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, 0)

#define BPF_TABLE_PINNED(_table_type, _key_type, _leaf_type, _name, _max_entries, _pinned) \
BPF_TABLE(_table_type ":" _pinned, _key_type, _leaf_type, _name, _max_entries)

// define a table same as above but allow it to be referenced by other modules
#define BPF_TABLE_PUBLIC(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
__attribute__((section("maps/export"))) \
struct _name##_table_t __##_name

// define a table that is shared across the programs in the same namespace
#define BPF_TABLE_SHARED(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
__attribute__((section("maps/shared"))) \
struct _name##_table_t __##_name

// Identifier for current CPU used in perf_submit and perf_read
// Prefer BPF_F_CURRENT_CPU flag, falls back to call helper for older kernel
// Can be overridden from BCC
#ifndef CUR_CPU_IDENTIFIER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
#else
#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
#endif
#endif

// Table for pushing custom events to userspace via perf ring buffer
#define BPF_PERF_OUTPUT(_name) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* map.perf_submit(ctx, data, data_size) */ \
  int (*perf_submit) (void *, void *, u32); \
  int (*perf_submit_skb) (void *, u32, void *, u32); \
  u32 max_entries; \
}; \
__attribute__((section("maps/perf_output"))) \
struct _name##_table_t _name = { .max_entries = 0 }

// Table for pushing custom events to userspace via ring buffer
#define BPF_RINGBUF_OUTPUT(_name, _num_pages) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* map.ringbuf_output(data, data_size, flags) */ \
  int (*ringbuf_output) (void *, u64, u64); \
  /* map.ringbuf_reserve(data_size) */ \
  void* (*ringbuf_reserve) (u64); \
  /* map.ringbuf_discard(data, flags) */ \
  void (*ringbuf_discard) (void *, u64); \
  /* map.ringbuf_submit(data, flags) */ \
  void (*ringbuf_submit) (void *, u64); \
  u32 max_entries; \
}; \
__attribute__((section("maps/ringbuf"))) \
struct _name##_table_t _name = { .max_entries = ((_num_pages) * PAGE_SIZE) }

// Table for reading hw perf cpu counters
#define BPF_PERF_ARRAY(_name, _max_entries) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* counter = map.perf_read(index) */ \
  u64 (*perf_read) (int); \
  int (*perf_counter_value) (int, void *, u32); \
  u32 max_entries; \
}; \
__attribute__((section("maps/perf_array"))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }

// Table for cgroup file descriptors
#define BPF_CGROUP_ARRAY(_name, _max_entries) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  int (*check_current_task) (int); \
  u32 max_entries; \
}; \
__attribute__((section("maps/cgroup_array"))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }

#define BPF_HASH1(_name) \
  BPF_TABLE("hash", u64, u64, _name, 10240)
#define BPF_HASH2(_name, _key_type) \
  BPF_TABLE("hash", _key_type, u64, _name, 10240)
#define BPF_HASH3(_name, _key_type, _leaf_type) \
  BPF_TABLE("hash", _key_type, _leaf_type, _name, 10240)
#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
  BPF_TABLE("hash", _key_type, _leaf_type, _name, _size)

// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME

// Define a hash function, some arguments optional
// BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3, BPF_HASH2, BPF_HASH1)(__VA_ARGS__)

#define BPF_ARRAY1(_name) \
  BPF_TABLE("array", int, u64, _name, 10240)
#define BPF_ARRAY2(_name, _leaf_type) \
  BPF_TABLE("array", int, _leaf_type, _name, 10240)
#define BPF_ARRAY3(_name, _leaf_type, _size) \
  BPF_TABLE("array", int, _leaf_type, _name, _size)

// helper for default-variable macro function
#define BPF_ARRAYX(_1, _2, _3, NAME, ...) NAME

// Define an array function, some arguments optional
// BPF_ARRAY(name, leaf_type=u64, size=10240)
#define BPF_ARRAY(...) \
  BPF_ARRAYX(__VA_ARGS__, BPF_ARRAY3, BPF_ARRAY2, BPF_ARRAY1)(__VA_ARGS__)

#define BPF_PERCPU_ARRAY1(_name)                        \
    BPF_TABLE("percpu_array", int, u64, _name, 10240)
#define BPF_PERCPU_ARRAY2(_name, _leaf_type) \
    BPF_TABLE("percpu_array", int, _leaf_type, _name, 10240)
#define BPF_PERCPU_ARRAY3(_name, _leaf_type, _size) \
    BPF_TABLE("percpu_array", int, _leaf_type, _name, _size)

// helper for default-variable macro function
#define BPF_PERCPU_ARRAYX(_1, _2, _3, NAME, ...) NAME

// Define an array function (per CPU), some arguments optional
// BPF_PERCPU_ARRAY(name, leaf_type=u64, size=10240)
#define BPF_PERCPU_ARRAY(...)                                           \
  BPF_PERCPU_ARRAYX(                                                    \
    __VA_ARGS__, BPF_PERCPU_ARRAY3, BPF_PERCPU_ARRAY2, BPF_PERCPU_ARRAY1) \
           (__VA_ARGS__)

#define BPF_HIST1(_name) \
  BPF_TABLE("histogram", int, u64, _name, 64)
#define BPF_HIST2(_name, _key_type) \
  BPF_TABLE("histogram", _key_type, u64, _name, 64)
#define BPF_HIST3(_name, _key_type, _size) \
  BPF_TABLE("histogram", _key_type, u64, _name, _size)
#define BPF_HISTX(_1, _2, _3, NAME, ...) NAME

// Define a histogram, some arguments optional
// BPF_HISTOGRAM(name, key_type=int, size=64)
#define BPF_HISTOGRAM(...) \
  BPF_HISTX(__VA_ARGS__, BPF_HIST3, BPF_HIST2, BPF_HIST1)(__VA_ARGS__)

#define BPF_LPM_TRIE1(_name) \
  BPF_F_TABLE("lpm_trie", u64, u64, _name, 10240, BPF_F_NO_PREALLOC)
#define BPF_LPM_TRIE2(_name, _key_type) \
  BPF_F_TABLE("lpm_trie", _key_type, u64, _name, 10240, BPF_F_NO_PREALLOC)
#define BPF_LPM_TRIE3(_name, _key_type, _leaf_type) \
  BPF_F_TABLE("lpm_trie", _key_type, _leaf_type, _name, 10240, BPF_F_NO_PREALLOC)
#define BPF_LPM_TRIE4(_name, _key_type, _leaf_type, _size) \
  BPF_F_TABLE("lpm_trie", _key_type, _leaf_type, _name, _size, BPF_F_NO_PREALLOC)
#define BPF_LPM_TRIEX(_1, _2, _3, _4, NAME, ...) NAME

// Define a LPM trie function, some arguments optional
// BPF_LPM_TRIE(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_LPM_TRIE(...) \
  BPF_LPM_TRIEX(__VA_ARGS__, BPF_LPM_TRIE4, BPF_LPM_TRIE3, BPF_LPM_TRIE2, BPF_LPM_TRIE1)(__VA_ARGS__)

struct bpf_stacktrace {
  u64 ip[BPF_MAX_STACK_DEPTH];
};

struct bpf_stacktrace_buildid {
  struct bpf_stack_build_id trace[BPF_MAX_STACK_DEPTH];
};

#define BPF_STACK_TRACE(_name, _max_entries) \
  BPF_TABLE("stacktrace", int, struct bpf_stacktrace, _name, roundup_pow_of_two(_max_entries))

#define BPF_STACK_TRACE_BUILDID(_name, _max_entries) \
  BPF_F_TABLE("stacktrace", int, struct bpf_stacktrace_buildid, _name, roundup_pow_of_two(_max_entries), BPF_F_STACK_BUILD_ID)

#define BPF_PROG_ARRAY(_name, _max_entries) \
  BPF_TABLE("prog", u32, u32, _name, _max_entries)

#define BPF_XDP_REDIRECT_MAP(_table_type, _leaf_type, _name, _max_entries) \
struct _name##_table_t { \
  u32 key; \
  _leaf_type leaf; \
  /* xdp_act = map.redirect_map(index, flag) */ \
  u64 (*redirect_map) (int, int); \
  u32 max_entries; \
}; \
__attribute__((section("maps/"_table_type))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }

#define BPF_DEVMAP(_name, _max_entries) \
  BPF_XDP_REDIRECT_MAP("devmap", int, _name, _max_entries)

#define BPF_CPUMAP(_name, _max_entries) \
  BPF_XDP_REDIRECT_MAP("cpumap", u32, _name, _max_entries)

#define BPF_XSKMAP(_name, _max_entries) \
struct _name##_table_t { \
  u32 key; \
  int leaf; \
  int * (*lookup) (int *); \
  /* xdp_act = map.redirect_map(index, flag) */ \
  u64 (*redirect_map) (int, int); \
  u32 max_entries; \
}; \
__attribute__((section("maps/xskmap"))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }

#define BPF_ARRAY_OF_MAPS(_name, _inner_map_name, _max_entries) \
  BPF_TABLE("array_of_maps$" _inner_map_name, int, int, _name, _max_entries)

#define BPF_HASH_OF_MAPS(_name, _inner_map_name, _max_entries) \
  BPF_TABLE("hash_of_maps$" _inner_map_name, int, int, _name, _max_entries)

#define BPF_SK_STORAGE(_name, _leaf_type) \
struct _name##_table_t { \
  int key; \
  _leaf_type leaf; \
  void * (*sk_storage_get) (void *, void *, int); \
  int (*sk_storage_delete) (void *); \
  u32 flags; \
}; \
__attribute__((section("maps/sk_storage"))) \
struct _name##_table_t _name = { .flags = BPF_F_NO_PREALLOC }; \
BPF_ANNOTATE_KV_PAIR(_name, int, _leaf_type)

#define BPF_SOCKMAP_COMMON(_name, _max_entries, _kind, _helper_name) \
struct _name##_table_t { \
  u32 key; \
  int leaf; \
  int (*update) (u32 *, int *); \
  int (*delete) (int *); \
  /* ret = map.sock_map_update(ctx, key, flag) */ \
  int (* _helper_name) (void *, void *, u64); \
  u32 max_entries; \
}; \
__attribute__((section("maps/" _kind))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR(_name, u32, int)

#define BPF_SOCKMAP(_name, _max_entries) \
  BPF_SOCKMAP_COMMON(_name, _max_entries, "sockmap", sock_map_update)

#define BPF_SOCKHASH(_name, _max_entries) \
  BPF_SOCKMAP_COMMON(_name, _max_entries, "sockhash", sock_hash_update)

#define BPF_CGROUP_STORAGE_COMMON(_name, _leaf_type, _kind) \
struct _name##_table_t { \
  struct bpf_cgroup_storage_key key; \
  _leaf_type leaf; \
  _leaf_type * (*lookup) (struct bpf_cgroup_storage_key *); \
  int (*update) (struct bpf_cgroup_storage_key *, _leaf_type *); \
  int (*get_local_storage) (u64); \
}; \
__attribute__((section("maps/" _kind))) \
struct _name##_table_t _name = { 0 }; \
BPF_ANNOTATE_KV_PAIR(_name, struct bpf_cgroup_storage_key, _leaf_type)

#define BPF_CGROUP_STORAGE(_name, _leaf_type) \
  BPF_CGROUP_STORAGE_COMMON(_name, _leaf_type, "cgroup_storage")

#define BPF_PERCPU_CGROUP_STORAGE(_name, _leaf_type) \
  BPF_CGROUP_STORAGE_COMMON(_name, _leaf_type, "percpu_cgroup_storage")

// packet parsing state machine helpers
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

#ifdef LINUX_VERSION_CODE_OVERRIDE
unsigned _version BCC_SEC("version") = LINUX_VERSION_CODE_OVERRIDE;
#else
unsigned _version BCC_SEC("version") = LINUX_VERSION_CODE;
#endif

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
  (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, u64 flags) =
  (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
  (void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, u64 size, const void *unsafe_ptr) =
  (void *) BPF_FUNC_probe_read;
static u64 (*bpf_ktime_get_ns)(void) =
  (void *) BPF_FUNC_ktime_get_ns;
static u32 (*bpf_get_prandom_u32)(void) =
  (void *) BPF_FUNC_get_prandom_u32;
static int (*bpf_trace_printk_)(const char *fmt, u64 fmt_size, ...) =
  (void *) BPF_FUNC_trace_printk;
static int (*bpf_probe_read_str)(void *dst, u64 size, const void *unsafe_ptr) =
  (void *) BPF_FUNC_probe_read_str;
int bpf_trace_printk(const char *fmt, ...) asm("llvm.bpf.extra");
static inline __attribute__((always_inline))
void bpf_tail_call_(u64 map_fd, void *ctx, int index) {
  ((void (*)(void *, u64, int))BPF_FUNC_tail_call)(ctx, map_fd, index);
}
static int (*bpf_clone_redirect)(void *ctx, int ifindex, u32 flags) =
  (void *) BPF_FUNC_clone_redirect;
static u64 (*bpf_get_smp_processor_id)(void) =
  (void *) BPF_FUNC_get_smp_processor_id;
static u64 (*bpf_get_current_pid_tgid)(void) =
  (void *) BPF_FUNC_get_current_pid_tgid;
static u64 (*bpf_get_current_uid_gid)(void) =
  (void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
  (void *) BPF_FUNC_get_current_comm;
static u64 (*bpf_get_cgroup_classid)(void *ctx) =
  (void *) BPF_FUNC_get_cgroup_classid;
static u64 (*bpf_skb_vlan_push)(void *ctx, u16 proto, u16 vlan_tci) =
  (void *) BPF_FUNC_skb_vlan_push;
static u64 (*bpf_skb_vlan_pop)(void *ctx) =
  (void *) BPF_FUNC_skb_vlan_pop;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *to, u32 size, u64 flags) =
  (void *) BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *from, u32 size, u64 flags) =
  (void *) BPF_FUNC_skb_set_tunnel_key;
static u64 (*bpf_perf_event_read)(void *map, u64 flags) =
  (void *) BPF_FUNC_perf_event_read;
static int (*bpf_redirect)(int ifindex, u32 flags) =
  (void *) BPF_FUNC_redirect;
static u32 (*bpf_get_route_realm)(void *ctx) =
  (void *) BPF_FUNC_get_route_realm;
static int (*bpf_perf_event_output)(void *ctx, void *map, u64 index, void *data, u32 size) =
  (void *) BPF_FUNC_perf_event_output;
static int (*bpf_skb_load_bytes)(void *ctx, int offset, void *to, u32 len) =
  (void *) BPF_FUNC_skb_load_bytes;
static int (*bpf_perf_event_read_value)(void *map, u64 flags, void *buf, u32 buf_size) =
  (void *) BPF_FUNC_perf_event_read_value;
static int (*bpf_perf_prog_read_value)(void *ctx, void *buf, u32 buf_size) =
  (void *) BPF_FUNC_perf_prog_read_value;
static int (*bpf_current_task_under_cgroup)(void *map, int index) =
  (void *) BPF_FUNC_current_task_under_cgroup;
static u32 (*bpf_get_socket_cookie)(void *ctx) =
  (void *) BPF_FUNC_get_socket_cookie;
static u64 (*bpf_get_socket_uid)(void *ctx) =
  (void *) BPF_FUNC_get_socket_uid;
static int (*bpf_getsockopt)(void *ctx, int level, int optname, void *optval, int optlen) =
  (void *) BPF_FUNC_getsockopt;
static int (*bpf_redirect_map)(void *map, int key, int flags) =
  (void *) BPF_FUNC_redirect_map;
static int (*bpf_set_hash)(void *ctx, u32 hash) =
  (void *) BPF_FUNC_set_hash;
static int (*bpf_setsockopt)(void *ctx, int level, int optname, void *optval, int optlen) =
  (void *) BPF_FUNC_setsockopt;
static int (*bpf_skb_adjust_room)(void *ctx, int len_diff, u32 mode, u64 flags) =
  (void *) BPF_FUNC_skb_adjust_room;
static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) =
  (void *) BPF_FUNC_skb_under_cgroup;
static struct bpf_sock *(*bpf_skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, int size,
                                              unsigned long long netns_id,
                                              unsigned long long flags) =
  (void *) BPF_FUNC_skc_lookup_tcp;
static int (*bpf_sk_redirect_map)(void *ctx, void *map, int key, int flags) =
  (void *) BPF_FUNC_sk_redirect_map;
static int (*bpf_sock_map_update)(void *map, void *key, void *value, unsigned long long flags) =
  (void *) BPF_FUNC_sock_map_update;
static int (*bpf_strtol)(const char *buf, size_t buf_len, u64 flags, long *res) =
  (void *) BPF_FUNC_strtol;
static int (*bpf_strtoul)(const char *buf, size_t buf_len, u64 flags, unsigned long *res) =
  (void *) BPF_FUNC_strtoul;
static int (*bpf_sysctl_get_current_value)(struct bpf_sysctl *ctx, char *buf, size_t buf_len) =
  (void *) BPF_FUNC_sysctl_get_current_value;
static int (*bpf_sysctl_get_name)(struct bpf_sysctl *ctx, char *buf, size_t buf_len, u64 flags) =
  (void *) BPF_FUNC_sysctl_get_name;
static int (*bpf_sysctl_get_new_value)(struct bpf_sysctl *ctx, char *buf, size_t buf_len) =
  (void *) BPF_FUNC_sysctl_get_new_value;
static int (*bpf_sysctl_set_new_value)(struct bpf_sysctl *ctx, const char *buf, size_t buf_len) =
  (void *) BPF_FUNC_sysctl_set_new_value;
static int (*bpf_tcp_check_syncookie)(void *sk, void *ip, int ip_len, void *tcp,
                                      int tcp_len) =
  (void *) BPF_FUNC_tcp_check_syncookie;
static int (*bpf_xdp_adjust_meta)(void *ctx, int offset) =
  (void *) BPF_FUNC_xdp_adjust_meta;

/* bcc_get_stackid will return a negative value in the case of an error
 *
 * BPF_STACK_TRACE(_name, _size) will allocate space for _size stack traces.
 *  -ENOMEM will be returned when this limit is reached.
 *
 * -EFAULT is typically returned when requesting user-space stack straces (using
 * BPF_F_USER_STACK) for kernel threads. However, a valid stackid may be
 * returned in some cases; consider a tracepoint or kprobe executing in the
 * kernel context. Given this you can typically ignore -EFAULT errors when
 * retrieving user-space stack traces.
 */
static int (*bcc_get_stackid_)(void *ctx, void *map, u64 flags) =
  (void *) BPF_FUNC_get_stackid;
static inline __attribute__((always_inline))
int bcc_get_stackid(uintptr_t map, void *ctx, u64 flags) {
  return bcc_get_stackid_(ctx, (void *)map, flags);
}

static int (*bpf_csum_diff)(void *from, u64 from_size, void *to, u64 to_size, u64 seed) =
  (void *) BPF_FUNC_csum_diff;
static int (*bpf_skb_get_tunnel_opt)(void *ctx, void *md, u32 size) =
  (void *) BPF_FUNC_skb_get_tunnel_opt;
static int (*bpf_skb_set_tunnel_opt)(void *ctx, void *md, u32 size) =
  (void *) BPF_FUNC_skb_set_tunnel_opt;
static int (*bpf_skb_change_proto)(void *ctx, u16 proto, u64 flags) =
  (void *) BPF_FUNC_skb_change_proto;
static int (*bpf_skb_change_type)(void *ctx, u32 type) =
  (void *) BPF_FUNC_skb_change_type;
static u32 (*bpf_get_hash_recalc)(void *ctx) =
  (void *) BPF_FUNC_get_hash_recalc;
static u64 (*bpf_get_current_task)(void) =
  (void *) BPF_FUNC_get_current_task;
static int (*bpf_probe_write_user)(void *dst, void *src, u32 size) =
  (void *) BPF_FUNC_probe_write_user;
static int (*bpf_skb_change_tail)(void *ctx, u32 new_len, u64 flags) =
  (void *) BPF_FUNC_skb_change_tail;
static int (*bpf_skb_pull_data)(void *ctx, u32 len) =
  (void *) BPF_FUNC_skb_pull_data;
static int (*bpf_csum_update)(void *ctx, u16 csum) =
  (void *) BPF_FUNC_csum_update;
static int (*bpf_set_hash_invalid)(void *ctx) =
  (void *) BPF_FUNC_set_hash_invalid;
static int (*bpf_get_numa_node_id)(void) =
  (void *) BPF_FUNC_get_numa_node_id;
static int (*bpf_skb_change_head)(void *ctx, u32 len, u64 flags) =
  (void *) BPF_FUNC_skb_change_head;
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
  (void *) BPF_FUNC_xdp_adjust_head;
static int (*bpf_override_return)(void *pt_regs, unsigned long rc) =
  (void *) BPF_FUNC_override_return;
static int (*bpf_sock_ops_cb_flags_set)(void *skops, int flags) =
  (void *) BPF_FUNC_sock_ops_cb_flags_set;
static int (*bpf_msg_redirect_map)(void *msg, void *map, u32 key, u64 flags) =
  (void *) BPF_FUNC_msg_redirect_map;
static int (*bpf_msg_apply_bytes)(void *msg, u32 bytes) =
  (void *) BPF_FUNC_msg_apply_bytes;
static int (*bpf_msg_cork_bytes)(void *msg, u32 bytes) =
  (void *) BPF_FUNC_msg_cork_bytes;
static int (*bpf_msg_pull_data)(void *msg, u32 start, u32 end, u64 flags) =
  (void *) BPF_FUNC_msg_pull_data;
static int (*bpf_bind)(void *ctx, void *addr, int addr_len) =
  (void *) BPF_FUNC_bind;
static int (*bpf_xdp_adjust_tail)(void *ctx, int offset) =
  (void *) BPF_FUNC_xdp_adjust_tail;
static int (*bpf_skb_get_xfrm_state)(void *ctx, u32 index, void *xfrm_state, u32 size, u64 flags) =
  (void *) BPF_FUNC_skb_get_xfrm_state;
static int (*bpf_get_stack)(void *ctx, void *buf, u32 size, u64 flags) =
  (void *) BPF_FUNC_get_stack;
static int (*bpf_skb_load_bytes_relative)(void *ctx, u32 offset, void *to, u32 len, u32 start_header) =
  (void *) BPF_FUNC_skb_load_bytes_relative;
static int (*bpf_fib_lookup)(void *ctx, void *params, int plen, u32 flags) =
  (void *) BPF_FUNC_fib_lookup;
static int (*bpf_sock_hash_update)(void *ctx, void *map, void *key, u64 flags) =
  (void *) BPF_FUNC_sock_hash_update;
static int (*bpf_msg_redirect_hash)(void *ctx, void *map, void *key, u64 flags) =
  (void *) BPF_FUNC_msg_redirect_hash;
static int (*bpf_sk_redirect_hash)(void *ctx, void *map, void *key, u64 flags) =
  (void *) BPF_FUNC_sk_redirect_hash;
static int (*bpf_lwt_push_encap)(void *skb, u32 type, void *hdr, u32 len) =
  (void *) BPF_FUNC_lwt_push_encap;
static int (*bpf_lwt_seg6_store_bytes)(void *ctx, u32 offset, const void *from, u32 len) =
  (void *) BPF_FUNC_lwt_seg6_store_bytes;
static int (*bpf_lwt_seg6_adjust_srh)(void *ctx, u32 offset, s32 delta) =
  (void *) BPF_FUNC_lwt_seg6_adjust_srh;
static int (*bpf_lwt_seg6_action)(void *ctx, u32 action, void *param, u32 param_len) =
  (void *) BPF_FUNC_lwt_seg6_action;
static int (*bpf_rc_keydown)(void *ctx, u32 protocol, u64 scancode, u32 toggle) =
  (void *) BPF_FUNC_rc_keydown;
static int (*bpf_rc_repeat)(void *ctx) =
  (void *) BPF_FUNC_rc_repeat;
static u64 (*bpf_skb_cgroup_id)(void *skb) =
  (void *) BPF_FUNC_skb_cgroup_id;
static u64 (*bpf_get_current_cgroup_id)(void) =
  (void *) BPF_FUNC_get_current_cgroup_id;
static u64 (*bpf_skb_ancestor_cgroup_id)(void *skb, int ancestor_level) =
  (void *) BPF_FUNC_skb_ancestor_cgroup_id;
static void * (*bpf_get_local_storage)(void *map, u64 flags) =
  (void *) BPF_FUNC_get_local_storage;
static int (*bpf_sk_select_reuseport)(void *reuse, void *map, void *key, u64 flags) =
  (void *) BPF_FUNC_sk_select_reuseport;
static struct bpf_sock *(*bpf_sk_lookup_tcp)(void *ctx,
                                             struct bpf_sock_tuple *tuple,
                                             int size, unsigned int netns_id,
                                             unsigned long long flags) =
  (void *) BPF_FUNC_sk_lookup_tcp;
static struct bpf_sock *(*bpf_sk_lookup_udp)(void *ctx,
                                             struct bpf_sock_tuple *tuple,
                                             int size, unsigned int netns_id,
                                             unsigned long long flags) =
  (void *) BPF_FUNC_sk_lookup_udp;
static int (*bpf_sk_release)(void *sk) =
  (void *) BPF_FUNC_sk_release;
static int (*bpf_map_push_elem)(void *map, const void *value, u64 flags) =
  (void *) BPF_FUNC_map_push_elem;
static int (*bpf_map_pop_elem)(void *map, void *value) =
  (void *) BPF_FUNC_map_pop_elem;
static int (*bpf_map_peek_elem)(void *map, void *value) =
  (void *) BPF_FUNC_map_peek_elem;
static int (*bpf_msg_push_data)(void *skb, u32 start, u32 len, u64 flags) =
  (void *) BPF_FUNC_msg_push_data;
static int (*bpf_msg_pop_data)(void *msg, u32 start, u32 pop, u64 flags) =
  (void *) BPF_FUNC_msg_pop_data;
static int (*bpf_rc_pointer_rel)(void *ctx, s32 rel_x, s32 rel_y) =
  (void *) BPF_FUNC_rc_pointer_rel;
static void (*bpf_spin_lock)(struct bpf_spin_lock *lock) =
  (void *) BPF_FUNC_spin_lock;
static void (*bpf_spin_unlock)(struct bpf_spin_lock *lock) =
  (void *) BPF_FUNC_spin_unlock;
static struct bpf_sock *(*bpf_sk_fullsock)(struct bpf_sock *sk) =
  (void *) BPF_FUNC_sk_fullsock;
static struct bpf_tcp_sock *(*bpf_tcp_sock)(struct bpf_sock *sk) =
  (void *) BPF_FUNC_tcp_sock;
static int (*bpf_skb_ecn_set_ce)(void *ctx) =
  (void *) BPF_FUNC_skb_ecn_set_ce;
static struct bpf_sock *(*bpf_get_listener_sock)(struct bpf_sock *sk) =
  (void *) BPF_FUNC_get_listener_sock;
static void *(*bpf_sk_storage_get)(void *map, void *sk,
                                   void *value, __u64 flags) =
  (void *) BPF_FUNC_sk_storage_get;
static int (*bpf_sk_storage_delete)(void *map, void *sk) =
  (void *)BPF_FUNC_sk_storage_delete;
static int (*bpf_send_signal)(unsigned sig) = (void *)BPF_FUNC_send_signal;
static long long (*bpf_tcp_gen_syncookie)(void *sk, void *ip,
                                          int ip_len, void *tcp, int tcp_len) =
  (void *) BPF_FUNC_tcp_gen_syncookie;
static int (*bpf_skb_output)(void *ctx, void *map, __u64 flags, void *data,
                             __u64 size) =
  (void *)BPF_FUNC_skb_output;

static int (*bpf_probe_read_user)(void *dst, __u32 size,
                                  const void *unsafe_ptr) =
  (void *)BPF_FUNC_probe_read_user;
static int (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                    const void *unsafe_ptr) =
  (void *)BPF_FUNC_probe_read_kernel;
static int (*bpf_probe_read_user_str)(void *dst, __u32 size,
            const void *unsafe_ptr) =
  (void *)BPF_FUNC_probe_read_user_str;
static int (*bpf_probe_read_kernel_str)(void *dst, __u32 size,
            const void *unsafe_ptr) =
  (void *)BPF_FUNC_probe_read_kernel_str;
static int (*bpf_tcp_send_ack)(void *tp, __u32 rcv_nxt) =
  (void *)BPF_FUNC_tcp_send_ack;
static int (*bpf_send_signal_thread)(__u32 sig) =
  (void *)BPF_FUNC_send_signal_thread;
static __u64 (*bpf_jiffies64)(void) = (void *)BPF_FUNC_jiffies64;

struct bpf_perf_event_data;
static int (*bpf_read_branch_records)(struct bpf_perf_event_data *ctx, void *buf,
                                      __u32 size, __u64 flags) =
  (void *)BPF_FUNC_read_branch_records;
static int (*bpf_get_ns_current_pid_tgid)(__u64 dev, __u64 ino,
                                          struct bpf_pidns_info *nsdata,
                                          __u32 size) =
  (void *)BPF_FUNC_get_ns_current_pid_tgid;

struct bpf_map;
static int (*bpf_xdp_output)(void *ctx, struct bpf_map *map, __u64 flags,
                             void *data, __u64 size) =
  (void *)BPF_FUNC_xdp_output;
static __u64 (*bpf_get_netns_cookie)(void *ctx) = (void *)BPF_FUNC_get_netns_cookie;
static __u64 (*bpf_get_current_ancestor_cgroup_id)(int ancestor_level) =
  (void *)BPF_FUNC_get_current_ancestor_cgroup_id;

struct sk_buff;
static int (*bpf_sk_assign)(void *skb, void *sk, __u64 flags) =
  (void *)BPF_FUNC_sk_assign;

static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *)BPF_FUNC_ktime_get_boot_ns;

struct seq_file;
static int (*bpf_seq_printf)(struct seq_file *m, const char *fmt, __u32 fmt_size,
			     const void *data, __u32 data_len) =
  (void *)BPF_FUNC_seq_printf;
static int (*bpf_seq_write)(struct seq_file *m, const void *data, __u32 len) =
  (void *)BPF_FUNC_seq_write;

static __u64 (*bpf_sk_cgroup_id)(void *sk) = (void *)BPF_FUNC_sk_cgroup_id;
static __u64 (*bpf_sk_ancestor_cgroup_id)(void *sk, int ancestor_level) =
  (void *)BPF_FUNC_sk_ancestor_cgroup_id;

static int (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) =
  (void *)BPF_FUNC_ringbuf_output;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
  (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) =
  (void *)BPF_FUNC_ringbuf_submit;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) =
  (void *)BPF_FUNC_ringbuf_discard;
static __u64 (*bpf_ringbuf_query)(void *ringbuf, __u64 flags) =
  (void *)BPF_FUNC_ringbuf_query;

static int (*bpf_csum_level)(struct __sk_buff *skb, __u64 level) =
  (void *)BPF_FUNC_csum_level;

struct tcp6_sock;
struct tcp_sock;
struct tcp_timewait_sock;
struct tcp_request_sock;
struct udp6_sock;
static struct tcp6_sock *(*bpf_skc_to_tcp6_sock)(void *sk) =
  (void *)BPF_FUNC_skc_to_tcp6_sock;
static struct tcp_sock *(*bpf_skc_to_tcp_sock)(void *sk) =
  (void *)BPF_FUNC_skc_to_tcp_sock;
static struct tcp_timewait_sock *(*bpf_skc_to_tcp_timewait_sock)(void *sk) =
  (void *)BPF_FUNC_skc_to_tcp_timewait_sock;
static struct tcp_request_sock *(*bpf_skc_to_tcp_request_sock)(void *sk) =
  (void *)BPF_FUNC_skc_to_tcp_request_sock;
static struct udp6_sock *(*bpf_skc_to_udp6_sock)(void *sk) =
  (void *)BPF_FUNC_skc_to_udp6_sock;

struct task_struct;
static long (*bpf_get_task_stack)(struct task_struct *task, void *buf,
				  __u32 size, __u64 flags) =
  (void *)BPF_FUNC_get_task_stack;

struct bpf_sock_ops;
static long (*bpf_load_hdr_opt)(struct bpf_sock_ops *skops, void *searchby_res,
                                u32 len, u64 flags) =
  (void *)BPF_FUNC_load_hdr_opt;
static long (*bpf_store_hdr_opt)(struct bpf_sock_ops *skops, const void *from,
                                 u32 len, u64 flags) =
  (void *)BPF_FUNC_store_hdr_opt;
static long (*bpf_reserve_hdr_opt)(struct bpf_sock_ops *skops, u32 len,
                                   u64 flags) =
  (void *)BPF_FUNC_reserve_hdr_opt;
static void *(*bpf_inode_storage_get)(struct bpf_map *map, void *inode,
                                      void *value, u64 flags) =
  (void *)BPF_FUNC_inode_storage_get;
static int (*bpf_inode_storage_delete)(struct bpf_map *map, void *inode) =
  (void *)BPF_FUNC_inode_storage_delete;
struct path;
static long (*bpf_d_path)(struct path *path, char *buf, u32 sz) =
  (void *)BPF_FUNC_d_path;
static long (*bpf_copy_from_user)(void *dst, u32 size, const void *user_ptr) =
  (void *)BPF_FUNC_copy_from_user;

static long (*bpf_snprintf_btf)(char *str, u32 str_size, struct btf_ptr *ptr,
				u32 btf_ptr_size, u64 flags) =
  (void *)BPF_FUNC_snprintf_btf;
static long (*bpf_seq_printf_btf)(struct seq_file *m, struct btf_ptr *ptr,
				  u32 ptr_size, u64 flags) =
  (void *)BPF_FUNC_seq_printf_btf;
static u64 (*bpf_skb_cgroup_classid)(struct sk_buff *skb) =
  (void *)BPF_FUNC_skb_cgroup_classid;
static long (*bpf_redirect_neigh)(u32 ifindex, struct bpf_redir_neigh *params,
				  u64 flags) =
  (void *)BPF_FUNC_redirect_neigh;
static void * (*bpf_per_cpu_ptr)(const void *percpu_ptr, u32 cpu) =
  (void *)BPF_FUNC_bpf_per_cpu_ptr;
static void * (*bpf_this_cpu_ptr)(const void *percpu_ptr) =
  (void *)BPF_FUNC_bpf_this_cpu_ptr;
long (*bpf_redirect_peer)(u32 ifindex, u64 flags) = (void *)BPF_FUNC_redirect_peer;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
  unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
  unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
  unsigned long long off) asm("llvm.bpf.load.word");

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
};

static int (*bpf_skb_store_bytes)(void *ctx, unsigned long long off, void *from,
                                  unsigned long long len, unsigned long long flags) =
  (void *) BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, unsigned long long off, unsigned long long from,
                                  unsigned long long to, unsigned long long flags) =
  (void *) BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, unsigned long long off, unsigned long long from,
                                  unsigned long long to, unsigned long long flags) =
  (void *) BPF_FUNC_l4_csum_replace;

static inline __attribute__((always_inline))
u16 bpf_ntohs(u16 val) {
  /* will be recognized by gcc into rotate insn and eventually rolw 8 */
  return (val << 8) | (val >> 8);
}

static inline __attribute__((always_inline))
u32 bpf_ntohl(u32 val) {
  /* gcc will use bswapsi2 insn */
  return __builtin_bswap32(val);
}

static inline __attribute__((always_inline))
u64 bpf_ntohll(u64 val) {
  /* gcc will use bswapdi2 insn */
  return __builtin_bswap64(val);
}

static inline __attribute__((always_inline))
unsigned __int128 bpf_ntoh128(unsigned __int128 val) {
  return (((unsigned __int128)bpf_ntohll(val) << 64) | (u64)bpf_ntohll(val >> 64));
}

static inline __attribute__((always_inline))
u16 bpf_htons(u16 val) {
  return bpf_ntohs(val);
}

static inline __attribute__((always_inline))
u32 bpf_htonl(u32 val) {
  return bpf_ntohl(val);
}

static inline __attribute__((always_inline))
u64 bpf_htonll(u64 val) {
  return bpf_ntohll(val);
}

static inline __attribute__((always_inline))
unsigned __int128 bpf_hton128(unsigned __int128 val) {
  return bpf_ntoh128(val);
}

static inline __attribute__((always_inline))
u64 load_dword(void *skb, u64 off) {
  return ((u64)load_word(skb, off) << 32) | load_word(skb, off + 4);
}

void bpf_store_byte(void *skb, u64 off, u64 val) asm("llvm.bpf.store.byte");
void bpf_store_half(void *skb, u64 off, u64 val) asm("llvm.bpf.store.half");
void bpf_store_word(void *skb, u64 off, u64 val) asm("llvm.bpf.store.word");
u64 bpf_pseudo_fd(u64, u64) asm("llvm.bpf.pseudo");

static inline void __attribute__((always_inline))
bpf_store_dword(void *skb, u64 off, u64 val) {
  bpf_store_word(skb, off, (u32)val);
  bpf_store_word(skb, off + 4, val >> 32);
}

#define MASK(_n) ((_n) < 64 ? (1ull << (_n)) - 1 : ((u64)-1LL))
#define MASK128(_n) ((_n) < 128 ? ((unsigned __int128)1 << (_n)) - 1 : ((unsigned __int128)-1))

static inline __attribute__((always_inline))
unsigned int bpf_log2(unsigned int v)
{
  unsigned int r;
  unsigned int shift;

  r = (v > 0xFFFF) << 4; v >>= r;
  shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
  shift = (v > 0xF) << 2; v >>= shift; r |= shift;
  shift = (v > 0x3) << 1; v >>= shift; r |= shift;
  r |= (v >> 1);
  return r;
}

static inline __attribute__((always_inline))
unsigned int bpf_log2l(unsigned long v)
{
  unsigned int hi = v >> 32;
  if (hi)
    return bpf_log2(hi) + 32 + 1;
  else
    return bpf_log2(v) + 1;
}

struct bpf_context;

static inline __attribute__((always_inline))
BCC_SEC("helpers")
u64 bpf_dext_pkt(void *pkt, u64 off, u64 bofs, u64 bsz) {
  if (bofs == 0 && bsz == 8) {
    return load_byte(pkt, off);
  } else if (bofs + bsz <= 8) {
    return load_byte(pkt, off) >> (8 - (bofs + bsz))  &  MASK(bsz);
  } else if (bofs == 0 && bsz == 16) {
    return load_half(pkt, off);
  } else if (bofs + bsz <= 16) {
    return load_half(pkt, off) >> (16 - (bofs + bsz))  &  MASK(bsz);
  } else if (bofs == 0 && bsz == 32) {
    return load_word(pkt, off);
  } else if (bofs + bsz <= 32) {
    return load_word(pkt, off) >> (32 - (bofs + bsz))  &  MASK(bsz);
  } else if (bofs == 0 && bsz == 64) {
    return load_dword(pkt, off);
  } else if (bofs + bsz <= 64) {
    return load_dword(pkt, off) >> (64 - (bofs + bsz))  &  MASK(bsz);
  }
  return 0;
}

static inline __attribute__((always_inline))
BCC_SEC("helpers")
void bpf_dins_pkt(void *pkt, u64 off, u64 bofs, u64 bsz, u64 val) {
  // The load_xxx function does a bswap before returning the short/word/dword,
  // so the value in register will always be host endian. However, the bytes
  // written back need to be in network order.
  if (bofs == 0 && bsz == 8) {
    bpf_skb_store_bytes(pkt, off, &val, 1, 0);
  } else if (bofs + bsz <= 8) {
    u8 v = load_byte(pkt, off);
    v &= ~(MASK(bsz) << (8 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (8 - (bofs + bsz)));
    bpf_skb_store_bytes(pkt, off, &v, 1, 0);
  } else if (bofs == 0 && bsz == 16) {
    u16 v = bpf_htons(val);
    bpf_skb_store_bytes(pkt, off, &v, 2, 0);
  } else if (bofs + bsz <= 16) {
    u16 v = load_half(pkt, off);
    v &= ~(MASK(bsz) << (16 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (16 - (bofs + bsz)));
    v = bpf_htons(v);
    bpf_skb_store_bytes(pkt, off, &v, 2, 0);
  } else if (bofs == 0 && bsz == 32) {
    u32 v = bpf_htonl(val);
    bpf_skb_store_bytes(pkt, off, &v, 4, 0);
  } else if (bofs + bsz <= 32) {
    u32 v = load_word(pkt, off);
    v &= ~(MASK(bsz) << (32 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (32 - (bofs + bsz)));
    v = bpf_htonl(v);
    bpf_skb_store_bytes(pkt, off, &v, 4, 0);
  } else if (bofs == 0 && bsz == 64) {
    u64 v = bpf_htonll(val);
    bpf_skb_store_bytes(pkt, off, &v, 8, 0);
  } else if (bofs + bsz <= 64) {
    u64 v = load_dword(pkt, off);
    v &= ~(MASK(bsz) << (64 - (bofs + bsz)));
    v |= ((val & MASK(bsz)) << (64 - (bofs + bsz)));
    v = bpf_htonll(v);
    bpf_skb_store_bytes(pkt, off, &v, 8, 0);
  }
}

static inline __attribute__((always_inline))
BCC_SEC("helpers")
void * bpf_map_lookup_elem_(uintptr_t map, void *key) {
  return bpf_map_lookup_elem((void *)map, key);
}

static inline __attribute__((always_inline))
BCC_SEC("helpers")
int bpf_map_update_elem_(uintptr_t map, void *key, void *value, u64 flags) {
  return bpf_map_update_elem((void *)map, key, value, flags);
}

static inline __attribute__((always_inline))
BCC_SEC("helpers")
int bpf_map_delete_elem_(uintptr_t map, void *key) {
  return bpf_map_delete_elem((void *)map, key);
}

static inline __attribute__((always_inline))
BCC_SEC("helpers")
int bpf_l3_csum_replace_(void *ctx, u64 off, u64 from, u64 to, u64 flags) {
  switch (flags & 0xf) {
    case 2:
      return bpf_l3_csum_replace(ctx, off, bpf_htons(from), bpf_htons(to), flags);
    case 4:
      return bpf_l3_csum_replace(ctx, off, bpf_htonl(from), bpf_htonl(to), flags);
    case 8:
      return bpf_l3_csum_replace(ctx, off, bpf_htonll(from), bpf_htonll(to), flags);
    default:
      {}
  }
  return bpf_l3_csum_replace(ctx, off, from, to, flags);
}

static inline __attribute__((always_inline))
BCC_SEC("helpers")
int bpf_l4_csum_replace_(void *ctx, u64 off, u64 from, u64 to, u64 flags) {
  switch (flags & 0xf) {
    case 2:
      return bpf_l4_csum_replace(ctx, off, bpf_htons(from), bpf_htons(to), flags);
    case 4:
      return bpf_l4_csum_replace(ctx, off, bpf_htonl(from), bpf_htonl(to), flags);
    case 8:
      return bpf_l4_csum_replace(ctx, off, bpf_htonll(from), bpf_htonll(to), flags);
    default:
      {}
  }
  return bpf_l4_csum_replace(ctx, off, from, to, flags);
}

int incr_cksum_l3(void *off, u64 oldval, u64 newval) asm("llvm.bpf.extra");
int incr_cksum_l4(void *off, u64 oldval, u64 newval, u64 flags) asm("llvm.bpf.extra");
int bpf_num_cpus() asm("llvm.bpf.extra");

struct pt_regs;
int bpf_usdt_readarg(int argc, struct pt_regs *ctx, void *arg) asm("llvm.bpf.extra");
int bpf_usdt_readarg_p(int argc, struct pt_regs *ctx, void *buf, u64 len) asm("llvm.bpf.extra");

/* Scan the ARCH passed in from ARCH env variable (see kbuild_helper.cc) */
#if defined(__TARGET_ARCH_x86)
#define bpf_target_x86
#define bpf_target_defined
#elif defined(__TARGET_ARCH_s390x)
#define bpf_target_s390x
#define bpf_target_defined
#elif defined(__TARGET_ARCH_arm64)
#define bpf_target_arm64
#define bpf_target_defined
#elif defined(__TARGET_ARCH_powerpc)
#define bpf_target_powerpc
#define bpf_target_defined
#else
#undef bpf_target_defined
#endif

/* Fall back to what the compiler says */
#ifndef bpf_target_defined
#if defined(__x86_64__)
#define bpf_target_x86
#elif defined(__s390x__)
#define bpf_target_s390x
#elif defined(__aarch64__)
#define bpf_target_arm64
#elif defined(__powerpc__)
#define bpf_target_powerpc
#endif
#endif

#if defined(bpf_target_powerpc)
#define PT_REGS_PARM1(ctx)	((ctx)->gpr[3])
#define PT_REGS_PARM2(ctx)	((ctx)->gpr[4])
#define PT_REGS_PARM3(ctx)	((ctx)->gpr[5])
#define PT_REGS_PARM4(ctx)	((ctx)->gpr[6])
#define PT_REGS_PARM5(ctx)	((ctx)->gpr[7])
#define PT_REGS_PARM6(ctx)	((ctx)->gpr[8])
#define PT_REGS_RC(ctx)		((ctx)->gpr[3])
#define PT_REGS_IP(ctx)		((ctx)->nip)
#define PT_REGS_SP(ctx)		((ctx)->gpr[1])
#elif defined(bpf_target_s390x)
#define PT_REGS_PARM1(x) ((x)->gprs[2])
#define PT_REGS_PARM2(x) ((x)->gprs[3])
#define PT_REGS_PARM3(x) ((x)->gprs[4])
#define PT_REGS_PARM4(x) ((x)->gprs[5])
#define PT_REGS_PARM5(x) ((x)->gprs[6])
#define PT_REGS_RET(x) ((x)->gprs[14])
#define PT_REGS_FP(x) ((x)->gprs[11]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->gprs[2])
#define PT_REGS_SP(x) ((x)->gprs[15])
#define PT_REGS_IP(x) ((x)->psw.addr)
#elif defined(bpf_target_x86)
#define PT_REGS_PARM1(ctx)	((ctx)->di)
#define PT_REGS_PARM2(ctx)	((ctx)->si)
#define PT_REGS_PARM3(ctx)	((ctx)->dx)
#define PT_REGS_PARM4(ctx)	((ctx)->cx)
#define PT_REGS_PARM5(ctx)	((ctx)->r8)
#define PT_REGS_PARM6(ctx)	((ctx)->r9)
#define PT_REGS_RET(ctx)	((ctx)->sp)
#define PT_REGS_FP(ctx)         ((ctx)->bp) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(ctx)		((ctx)->ax)
#define PT_REGS_IP(ctx)		((ctx)->ip)
#define PT_REGS_SP(ctx)		((ctx)->sp)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM1(x)	((x)->regs[0])
#define PT_REGS_PARM2(x)	((x)->regs[1])
#define PT_REGS_PARM3(x)	((x)->regs[2])
#define PT_REGS_PARM4(x)	((x)->regs[3])
#define PT_REGS_PARM5(x)	((x)->regs[4])
#define PT_REGS_PARM6(x)	((x)->regs[5])
#define PT_REGS_RET(x)		((x)->regs[30])
#define PT_REGS_FP(x)		((x)->regs[29]) /*  Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x)		((x)->regs[0])
#define PT_REGS_SP(x)		((x)->sp)
#define PT_REGS_IP(x)		((x)->pc)
#else
#error "bcc does not support this platform yet"
#endif

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
#define PT_REGS_SYSCALL_CTX(ctx)	((struct pt_regs *)PT_REGS_PARM1(ctx))
#else
#define PT_REGS_SYSCALL_CTX(ctx)	(ctx)
#endif
/* Helpers for syscall params. Pass in a ctx returned from PT_REGS_SYSCALL_CTX.
 */
#define PT_REGS_PARM1_SYSCALL(ctx)	PT_REGS_PARM1(ctx)
#define PT_REGS_PARM2_SYSCALL(ctx)	PT_REGS_PARM2(ctx)
#define PT_REGS_PARM3_SYSCALL(ctx)	PT_REGS_PARM3(ctx)
#if defined(bpf_target_x86)
#define PT_REGS_PARM4_SYSCALL(ctx)	((ctx)->r10) /* for syscall only */
#else
#define PT_REGS_PARM4_SYSCALL(ctx)	PT_REGS_PARM4(ctx)
#endif
#define PT_REGS_PARM5_SYSCALL(ctx)	PT_REGS_PARM5(ctx)
#ifdef PT_REGS_PARM6
#define PT_REGS_PARM6_SYSCALL(ctx)	PT_REGS_PARM6(ctx)
#endif

#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))

#define TRACEPOINT_PROBE(category, event) \
int tracepoint__##category##__##event(struct tracepoint__##category##__##event *args)

#define RAW_TRACEPOINT_PROBE(event) \
int raw_tracepoint__##event(struct bpf_raw_tracepoint_args *ctx)

/* BPF_PROG macro allows to define trampoline function,
 * borrowed from kernel bpf selftest code.
 */
#define ___bpf_concat(a, b) a ## b
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#define ___bpf_narg(...) \
        ___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define ___bpf_ctx_cast0() ctx
#define ___bpf_ctx_cast1(x) ___bpf_ctx_cast0(), (void *)ctx[0]
#define ___bpf_ctx_cast2(x, args...) ___bpf_ctx_cast1(args), (void *)ctx[1]
#define ___bpf_ctx_cast3(x, args...) ___bpf_ctx_cast2(args), (void *)ctx[2]
#define ___bpf_ctx_cast4(x, args...) ___bpf_ctx_cast3(args), (void *)ctx[3]
#define ___bpf_ctx_cast5(x, args...) ___bpf_ctx_cast4(args), (void *)ctx[4]
#define ___bpf_ctx_cast6(x, args...) ___bpf_ctx_cast5(args), (void *)ctx[5]
#define ___bpf_ctx_cast7(x, args...) ___bpf_ctx_cast6(args), (void *)ctx[6]
#define ___bpf_ctx_cast8(x, args...) ___bpf_ctx_cast7(args), (void *)ctx[7]
#define ___bpf_ctx_cast9(x, args...) ___bpf_ctx_cast8(args), (void *)ctx[8]
#define ___bpf_ctx_cast10(x, args...) ___bpf_ctx_cast9(args), (void *)ctx[9]
#define ___bpf_ctx_cast11(x, args...) ___bpf_ctx_cast10(args), (void *)ctx[10]
#define ___bpf_ctx_cast12(x, args...) ___bpf_ctx_cast11(args), (void *)ctx[11]
#define ___bpf_ctx_cast(args...) \
        ___bpf_apply(___bpf_ctx_cast, ___bpf_narg(args))(args)

#define BPF_PROG(name, args...)                                 \
int name(unsigned long long *ctx);                              \
__attribute__((always_inline))                                  \
static int ____##name(unsigned long long *ctx, ##args);         \
int name(unsigned long long *ctx)                               \
{                                                               \
        int __ret;                                              \
                                                                \
        _Pragma("GCC diagnostic push")                          \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")  \
        __ret = ____##name(___bpf_ctx_cast(args));              \
        _Pragma("GCC diagnostic pop")                           \
        return __ret;                                           \
}                                                               \
static int ____##name(unsigned long long *ctx, ##args)

#define KFUNC_PROBE(event, args...) \
        BPF_PROG(kfunc__ ## event, args)

#define KRETFUNC_PROBE(event, args...) \
        BPF_PROG(kretfunc__ ## event, args)

#define LSM_PROBE(event, args...) \
        BPF_PROG(lsm__ ## event, args)

#define BPF_ITER(target) \
        int bpf_iter__ ## target (struct bpf_iter__ ## target *ctx)

#define TP_DATA_LOC_READ_CONST(dst, field, length)                        \
        do {                                                              \
            unsigned short __offset = args->data_loc_##field & 0xFFFF;    \
            bpf_probe_read((void *)dst, length, (char *)args + __offset); \
        } while (0);

#define TP_DATA_LOC_READ(dst, field)                                        \
        do {                                                                \
            unsigned short __offset = args->data_loc_##field & 0xFFFF;      \
            unsigned short __length = args->data_loc_##field >> 16;         \
            bpf_probe_read((void *)dst, __length, (char *)args + __offset); \
        } while (0);

#endif
)********"
