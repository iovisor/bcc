#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#if defined(CONFIG_FUNCTION_TRACER)
/* In 4.18 and later, when CONFIG_FUNCTION_TRACER is defined, kernel Makefile adds
 * -DCC_USING_FENTRY. Let do the same for bpf programs.
 */
#define CC_USING_FENTRY
#endif

#ifdef PERF_MAX_STACK_DEPTH
#define BPF_MAX_STACK_DEPTH PERF_MAX_STACK_DEPTH
#else
#define BPF_MAX_STACK_DEPTH 127
#endif

#define BCC_SEC(NAME) __attribute__((section(NAME), used))

#ifdef B_WORKAROUND
#define BCC_SEC_HELPERS BCC_SEC("helpers")
#else
#define BCC_SEC_HELPERS
#endif


#ifndef CUR_CPU_IDENTIFIER
#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
#endif


#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)	\
        struct ____btf_map_##name {			\
                type_key key;				\
                type_val value;				\
        };						\
        struct ____btf_map_##name			\
        __attribute__ ((section(".maps." #name), used))	\
                ____btf_map_##name = { }

#define BPF_ANNOTATE_KV_PAIR_QUEUESTACK(name, type_val)  \
        struct ____btf_map_##name {     \
                type_val value;       \
        };            \
        struct ____btf_map_##name     \
        __attribute__ ((section(".maps." #name), used)) \
                ____btf_map_##name = { }

#define BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, _flags) \
struct { \
  __uint(type, _table_type);\
	__uint(max_entries, _max_entries);\
  __type(key, _key_type);\
	__type(value, _leaf_type);\
} _name  \
SEC(".maps") \

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

#define BPF_QUEUE_STACK3(_type, _name, _leaf_type, _max_entries) \
  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, 0)

#define BPF_QUEUE_STACK4(_type, _name, _leaf_type, _max_entries, _flags) \
  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, _flags)

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

#define BPF_TABLE_PINNED7(_table_type, _key_type, _leaf_type, _name, _max_entries, _pinned, _flags) \
  BPF_F_TABLE(_table_type ":" _pinned, _key_type, _leaf_type, _name, _max_entries, _flags)

#define BPF_TABLE_PINNED6(_table_type, _key_type, _leaf_type, _name, _max_entries, _pinned) \
  BPF_F_TABLE(_table_type ":" _pinned, _key_type, _leaf_type, _name, _max_entries, 0)

#define BPF_TABLE_PINNEDX(_1, _2, _3, _4, _5, _6, _7, NAME, ...) NAME

#define BPF_TABLE_PINNED(...) \
  BPF_TABLE_PINNEDX(__VA_ARGS__, BPF_TABLE_PINNED7, BPF_TABLE_PINNED6)(__VA_ARGS__)

#define BPF_TABLE_PUBLIC(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
__attribute__((section("maps/export"))) \
struct _name##_table_t __##_name

#define BPF_TABLE_SHARED(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
__attribute__((section("maps/shared"))) \
struct _name##_table_t __##_name

#define BPF_PERF_OUTPUT(_name) \
  struct { \
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
	__uint(value_size, sizeof(int)); \
	__uint(key_size, sizeof(int)); \
} _name SEC(".maps")

#define BPF_RINGBUF_OUTPUT(_name, _num_pages) \
struct { \
	__uint(type, BPF_MAP_TYPE_RINGBUF);\
	__uint(max_entries, ((_num_pages) * PAGE_SIZE));\
} _name SEC(".maps")\

#define BPF_PERF_ARRAY(_name, _max_entries) \
  struct { \
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
	__uint(value_size, sizeof(int)); \
	__uint(key_size, sizeof(int)); \
} _name SEC(".maps"); \

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
  BPF_TABLE(BPF_MAP_TYPE_HASH, u64, u64, _name, 10240)
#define BPF_HASH2(_name, _key_type) \
  BPF_TABLE(BPF_MAP_TYPE_HASH, _key_type, u64, _name, 10240)
#define BPF_HASH3(_name, _key_type, _leaf_type) \
  BPF_TABLE(BPF_MAP_TYPE_HASH, _key_type, _leaf_type, _name, 10240)
#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
  BPF_TABLE(BPF_MAP_TYPE_HASH, _key_type, _leaf_type, _name, _size)

#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME

#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3, BPF_HASH2, BPF_HASH1)(__VA_ARGS__)

#define BPF_PERCPU_HASH1(_name) \
  BPF_TABLE(BPF_MAP_TYPE_PERCPU_HASH, u64, u64, _name, 10240)
#define BPF_PERCPU_HASH2(_name, _key_type) \
  BPF_TABLE(BPF_MAP_TYPE_PERCPU_HASH, _key_type, u64, _name, 10240)
#define BPF_PERCPU_HASH3(_name, _key_type, _leaf_type) \
  BPF_TABLE(BPF_MAP_TYPE_PERCPU_HASH, _key_type, _leaf_type, _name, 10240)
#define BPF_PERCPU_HASH4(_name, _key_type, _leaf_type, _size) \
  BPF_TABLE(BPF_MAP_TYPE_PERCPU_HASH, _key_type, _leaf_type, _name, _size)

#define BPF_PERCPU_HASHX(_1, _2, _3, _4, NAME, ...) NAME

#define BPF_PERCPU_HASH(...)                                            \
  BPF_PERCPU_HASHX(                                                     \
    __VA_ARGS__, BPF_PERCPU_HASH4, BPF_PERCPU_HASH3, BPF_PERCPU_HASH2, BPF_PERCPU_HASH1) \
           (__VA_ARGS__)

#define BPF_ARRAY1(_name) \
  BPF_TABLE(BPF_MAP_TYPE_ARRAY, int, u64, _name, 10240)
#define BPF_ARRAY2(_name, _leaf_type) \
  BPF_TABLE(BPF_MAP_TYPE_ARRAY, int, _leaf_type, _name, 10240)
#define BPF_ARRAY3(_name, _leaf_type, _size) \
  BPF_TABLE(BPF_MAP_TYPE_ARRAY, int, _leaf_type, _name, _size)

#define BPF_ARRAYX(_1, _2, _3, NAME, ...) NAME

#define BPF_ARRAY(...) \
  BPF_ARRAYX(__VA_ARGS__, BPF_ARRAY3, BPF_ARRAY2, BPF_ARRAY1)(__VA_ARGS__)

#define BPF_PERCPU_ARRAY1(_name)                        \
    BPF_TABLE(BPF_MAP_TYPE_PERCPU_ARRAY, int, u64, _name, 10240)
#define BPF_PERCPU_ARRAY2(_name, _leaf_type) \
    BPF_TABLE(BPF_MAP_TYPE_PERCPU_ARRAY, int, _leaf_type, _name, 10240)
#define BPF_PERCPU_ARRAY3(_name, _leaf_type, _size) \
    BPF_TABLE(BPF_MAP_TYPE_PERCPU_ARRAY, int, _leaf_type, _name, _size)

#define BPF_PERCPU_ARRAYX(_1, _2, _3, NAME, ...) NAME

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

#define BPF_LPM_TRIE(...) \
  BPF_LPM_TRIEX(__VA_ARGS__, BPF_LPM_TRIE4, BPF_LPM_TRIE3, BPF_LPM_TRIE2, BPF_LPM_TRIE1)(__VA_ARGS__)

struct bpf_stacktrace {
  u64 ip[BPF_MAX_STACK_DEPTH];
};

struct bpf_stacktrace_buildid {
  struct bpf_stack_build_id trace[BPF_MAX_STACK_DEPTH];
};

#define roundup_pow_of_two(x) (x) // TODO: fix this

#define BPF_STACK_TRACE(_name, _max_entries) \
  BPF_TABLE(BPF_MAP_TYPE_STACK_TRACE, int, struct bpf_stacktrace, _name, roundup_pow_of_two(_max_entries))

#define BPF_STACK_TRACE_BUILDID(_name, _max_entries) \
  BPF_F_TABLE(BPF_MAP_TYPE_STACK_TRACE, int, struct bpf_stacktrace_buildid, _name, roundup_pow_of_two(_max_entries), BPF_F_STACK_BUILD_ID)

#define BPF_PROG_ARRAY(_name, _max_entries) \
  BPF_TABLE(BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _name, _max_entries)

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

#define _BPF_XSKMAP(_name, _max_entries, _pinned) \
struct _name##_table_t { \
  u32 key; \
  int leaf; \
  int * (*lookup) (int *); \
  u64 (*redirect_map) (int, int); \
  u32 max_entries; \
}; \
__attribute__((section("maps/xskmap" _pinned))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }
#define BPF_XSKMAP2(_name, _max_entries) _BPF_XSKMAP(_name, _max_entries, "")
#define BPF_XSKMAP3(_name, _max_entries, _pinned) _BPF_XSKMAP(_name, _max_entries, ":" _pinned)
#define BPF_XSKMAPX(_1, _2, _3, NAME, ...) NAME
#define BPF_XSKMAP(...) BPF_XSKMAPX(__VA_ARGS__, BPF_XSKMAP3, BPF_XSKMAP2)(__VA_ARGS__)

#define BPF_ARRAY_OF_MAPS(_name, _inner_map_name, _max_entries) \
  BPF_TABLE("array_of_maps$" _inner_map_name, int, int, _name, _max_entries)

#define BPF_HASH_OF_MAPS2(_name, _inner_map_name) \
  BPF_TABLE("hash_of_maps$" _inner_map_name, int, int, _name, 10240)
#define BPF_HASH_OF_MAPS3(_name, _key_type, _inner_map_name) \
  BPF_TABLE("hash_of_maps$" _inner_map_name, _key_type, int, _name, 10240)
#define BPF_HASH_OF_MAPS4(_name, _key_type, _inner_map_name, _max_entries) \
  BPF_TABLE("hash_of_maps$" _inner_map_name, _key_type, int, _name, _max_entries)

#define BPF_HASH_OF_MAPSX(_name, _2, _3, _4, NAME, ...) NAME

#define BPF_HASH_OF_MAPS(...) \
  BPF_HASH_OF_MAPSX(__VA_ARGS__, BPF_HASH_OF_MAPS4, BPF_HASH_OF_MAPS3, BPF_HASH_OF_MAPS2)(__VA_ARGS__)

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

#define BPF_INODE_STORAGE(_name, _leaf_type) \
struct _name##_table_t { \
  int key; \
  _leaf_type leaf; \
  void * (*inode_storage_get) (void *, void *, int); \
  int (*inode_storage_delete) (void *); \
  u32 flags; \
}; \
__attribute__((section("maps/inode_storage"))) \
struct _name##_table_t _name = { .flags = BPF_F_NO_PREALLOC }; \
BPF_ANNOTATE_KV_PAIR(_name, int, _leaf_type)

#define BPF_TASK_STORAGE(_name, _leaf_type) \
struct _name##_table_t { \
  int key; \
  _leaf_type leaf; \
  void * (*task_storage_get) (void *, void *, int); \
  int (*task_storage_delete) (void *); \
  u32 flags; \
}; \
__attribute__((section("maps/task_storage"))) \
struct _name##_table_t _name = { .flags = BPF_F_NO_PREALLOC }; \
BPF_ANNOTATE_KV_PAIR(_name, int, _leaf_type)

#define BPF_SOCKMAP_COMMON(_name, _max_entries, _kind, _helper_name) \
struct _name##_table_t { \
  u32 key; \
  int leaf; \
  int (*update) (u32 *, int *); \
  int (*delete) (u32 *); \
  int (* _helper_name) (void *, void *, u64); \
  u32 max_entries; \
}; \
__attribute__((section("maps/" _kind))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR(_name, u32, int)

#define BPF_SOCKMAP(_name, _max_entries) \
  BPF_SOCKMAP_COMMON(_name, _max_entries, "sockmap", sock_map_update)

#define BPF_SOCKHASH_COMMON(_name, _key_type, _max_entries) \
struct _name##_table_t {\
  _key_type key;\
  int leaf; \
  int (*update) (_key_type *, int *); \
  int (*delete) (_key_type *); \
  int (*sock_hash_update) (void *, void *, u64); \
  int (*msg_redirect_hash) (void *, void *, u64); \
  int (*sk_redirect_hash) (void *, void *, u64); \
  u32 max_entries; \
}; \
__attribute__((section("maps/sockhash"))) \
struct _name##_table_t _name = { .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR(_name, _key_type, int)

#define BPF_SOCKHASH1(_name) \
  BPF_SOCKHASH_COMMON(_name, u32, 10240)
#define BPF_SOCKHASH2(_name, _key_type) \
  BPF_SOCKHASH_COMMON(_name, _key_type, 10240)
#define BPF_SOCKHASH3(_name, _key_type, _max_entries) \
  BPF_SOCKHASH_COMMON(_name, _key_type, _max_entries)

#define BPF_SOCKHASHX(_1, _2, _3, NAME, ...) NAME
#define BPF_SOCKHASH(...) \
  BPF_SOCKHASHX(__VA_ARGS__, BPF_SOCKHASH3, BPF_SOCKHASH2, BPF_SOCKHASH1)(__VA_ARGS__)

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

#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

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
#elif defined(__TARGET_ARCH_mips)
#define bpf_target_mips
#define bpf_target_defined
#elif defined(__TARGET_ARCH_riscv64)
#define bpf_target_riscv64
#define bpf_target_defined
#elif defined(__TARGET_ARCH_loongarch)
#define bpf_target_loongarch
#define bpf_target_defined
#else
#undef bpf_target_defined
#endif

#ifndef bpf_target_defined
#if defined(__x86_64__)
#define bpf_target_x86
#elif defined(__s390x__)
#define bpf_target_s390x
#elif defined(__aarch64__)
#define bpf_target_arm64
#elif defined(__powerpc__)
#define bpf_target_powerpc
#elif defined(__mips__)
#define bpf_target_mips
#elif defined(__riscv) && (__riscv_xlen == 64)
#define bpf_target_riscv64
#elif defined(__loongarch__)
#define bpf_target_loongarch
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
#define PT_REGS_FP(ctx)         ((ctx)->bp)
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
#define PT_REGS_FP(x)		((x)->regs[29])
#define PT_REGS_RC(x)		((x)->regs[0])
#define PT_REGS_SP(x)		((x)->sp)
#define PT_REGS_IP(x)		((x)->pc)
#elif defined(bpf_target_mips)
#define PT_REGS_PARM1(x) ((x)->regs[4])
#define PT_REGS_PARM2(x) ((x)->regs[5])
#define PT_REGS_PARM3(x) ((x)->regs[6])
#define PT_REGS_PARM4(x) ((x)->regs[7])
#define PT_REGS_PARM5(x) ((x)->regs[8])
#define PT_REGS_PARM6(x) ((x)->regs[9])
#define PT_REGS_RET(x) ((x)->regs[31])
#define PT_REGS_FP(x) ((x)->regs[30]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->regs[2])
#define PT_REGS_SP(x) ((x)->regs[29])
#define PT_REGS_IP(x) ((x)->cp0_epc)
#elif defined(bpf_target_riscv64)
/* riscv64 provides struct user_pt_regs instead of struct pt_regs to userspace */
#define __PT_REGS_CAST(x) ((const struct user_regs_struct *)(x))
#define PT_REGS_PARM1(x) (__PT_REGS_CAST(x)->a0)
#define PT_REGS_PARM2(x) (__PT_REGS_CAST(x)->a1)
#define PT_REGS_PARM3(x) (__PT_REGS_CAST(x)->a2)
#define PT_REGS_PARM4(x) (__PT_REGS_CAST(x)->a3)
#define PT_REGS_PARM5(x) (__PT_REGS_CAST(x)->a4)
#define PT_REGS_PARM6(x) (__PT_REGS_CAST(x)->a5)
#define PT_REGS_RET(x) (__PT_REGS_CAST(x)->ra)
#define PT_REGS_FP(x) (__PT_REGS_CAST(x)->s0) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) (__PT_REGS_CAST(x)->a0)
#define PT_REGS_SP(x) (__PT_REGS_CAST(x)->sp)
#define PT_REGS_IP(x) (__PT_REGS_CAST(x)->pc)
#elif defined(bpf_target_loongarch)
#define PT_REGS_PARM1(x) ((x)->regs[4])
#define PT_REGS_PARM2(x) ((x)->regs[5])
#define PT_REGS_PARM3(x) ((x)->regs[6])
#define PT_REGS_PARM4(x) ((x)->regs[7])
#define PT_REGS_PARM5(x) ((x)->regs[8])
#define PT_REGS_PARM6(x) ((x)->regs[9])
#define PT_REGS_RET(x) ((x)->regs[1])
#define PT_REGS_FP(x) ((x)->regs[22]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->regs[4])
#define PT_REGS_SP(x) ((x)->regs[3])
#define PT_REGS_IP(x) ((x)->csr_era)
#else
#error "bcc does not support this platform yet"
#endif

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
#define PT_REGS_SYSCALL_CTX(ctx)	((struct pt_regs *)PT_REGS_PARM1(ctx))
#else
#define PT_REGS_SYSCALL_CTX(ctx)	(ctx)
#endif
#define PT_REGS_PARM1_SYSCALL(ctx)	PT_REGS_PARM1(ctx)
#define PT_REGS_PARM2_SYSCALL(ctx)	PT_REGS_PARM2(ctx)
#define PT_REGS_PARM3_SYSCALL(ctx)	PT_REGS_PARM3(ctx)
#if defined(bpf_target_x86)
#define PT_REGS_PARM4_SYSCALL(ctx)	((ctx)->r10)
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

#define KFUNC_PROBE(event, args...) \
        BPF_PROG(kfunc__ ## event, ##args)

#define KRETFUNC_PROBE(event, args...) \
        BPF_PROG(kretfunc__ ## event, ##args)

#define KMOD_RET(event, args...) \
        BPF_PROG(kmod_ret__ ## event, ##args)

#define LSM_PROBE(event, args...) \
        BPF_PROG(lsm__ ## event, ##args)

#define BPF_ITER(target) \
        int bpf_iter__ ## target (struct bpf_iter__ ## target *ctx)

#define TP_DATA_LOC_READ_CONST(dst, field, length)                        \
        do {                                                              \
            unsigned short __offset = args->data_loc_##field & 0xFFFF;    \
            bpf_core_read((void *)dst, length, (char *)args + __offset); \
        } while (0)

#define TP_DATA_LOC_READ(dst, field)                                        \
        do {                                                                \
            unsigned short __offset = args->data_loc_##field & 0xFFFF;      \
            unsigned short __length = args->data_loc_##field >> 16;         \
            bpf_core_read((void *)dst, __length, (char *)args + __offset); \
        } while (0)

#define TP_DATA_LOC_READ_STR(dst, field, length)                                \
        do {                                                                    \
            unsigned short __offset = args->data_loc_##field & 0xFFFF;          \
            bpf_probe_read_str((void *)dst, length, (char *)args + __offset);   \
        } while (0)

#endif
