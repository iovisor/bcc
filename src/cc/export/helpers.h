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

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_packet.h>
#include <linux/version.h>

#ifndef CONFIG_BPF_SYSCALL
#error "CONFIG_BPF_SYSCALL is undefined, please check your .config or ask your Linux distro to enable this feature"
#endif

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

// Changes to the macro require changes in BFrontendAction classes
#define BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries) \
struct _name##_table_t { \
  _key_type key; \
  _leaf_type leaf; \
  _leaf_type * (*lookup) (_key_type *); \
  _leaf_type * (*lookup_or_init) (_key_type *, _leaf_type *); \
  int (*update) (_key_type *, _leaf_type *); \
  int (*delete) (_key_type *); \
  void (*call) (void *, int index); \
  void (*increment) (_key_type); \
  _leaf_type data[_max_entries]; \
}; \
__attribute__((section("maps/" _table_type))) \
struct _name##_table_t _name

// define a table same as above but allow it to be referenced by other modules
#define BPF_TABLE_PUBLIC(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
__attribute__((section("maps/export"))) \
struct _name##_table_t __##_name

// Table for pushing custom events to userspace via ring buffer
#define BPF_PERF_OUTPUT(_name) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* map.perf_submit(ctx, data, data_size) */ \
  int (*perf_submit) (void *, void *, u32); \
  u32 data[0]; \
}; \
__attribute__((section("maps/perf_output"))) \
struct _name##_table_t _name

// Table for reading hw perf cpu counters
#define BPF_PERF_ARRAY(_name, _max_entries) \
struct _name##_table_t { \
  int key; \
  u32 leaf; \
  /* counter = map.perf_read(index) */ \
  u64 (*perf_read) (int); \
  u32 data[_max_entries]; \
}; \
__attribute__((section("maps/perf_array"))) \
struct _name##_table_t _name

#define BPF_HASH1(_name) \
  BPF_TABLE("hash", u64, u64, _name, 10240)
#define BPF_HASH2(_name, _key_type) \
  BPF_TABLE("hash", _key_type, u64, _name, 10240)
#define BPF_HASH3(_name, _key_type, _leaf_type) \
  BPF_TABLE("hash", _key_type, _leaf_type, _name, 10240)
// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, NAME, ...) NAME

// Define a hash function, some arguments optional
// BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH3, BPF_HASH2, BPF_HASH1)(__VA_ARGS__)

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

// packet parsing state machine helpers
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

char _license[4] SEC("license") = "GPL";

unsigned _version SEC("version") = LINUX_VERSION_CODE;

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
  (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, u64 flags) =
  (void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
  (void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, u64 size, void *unsafe_ptr) =
  (void *) BPF_FUNC_probe_read;
static u64 (*bpf_ktime_get_ns)(void) =
  (void *) BPF_FUNC_ktime_get_ns;
static u32 (*bpf_get_prandom_u32) =
  (void *) BPF_FUNC_get_prandom_u32;
static int (*bpf_trace_printk_)(const char *fmt, u64 fmt_size, ...) =
  (void *) BPF_FUNC_trace_printk;
int bpf_trace_printk(const char *fmt, ...) asm("llvm.bpf.extra");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static void bpf_tail_call_(u64 map_fd, void *ctx, int index) {
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
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
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
static int (*bpf_perf_event_read)(void *map, u32 index) =
  (void *) BPF_FUNC_perf_event_read;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static int (*bpf_redirect)(int ifindex, u32 flags) =
  (void *) BPF_FUNC_redirect;
static u32 (*bpf_get_route_realm)(void *ctx) =
  (void *) BPF_FUNC_get_route_realm;
static int (*bpf_perf_event_output)(void *ctx, void *map, u32 index, void *data, u32 size) =
  (void *) BPF_FUNC_perf_event_output;
#endif

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
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

static inline u16 bpf_ntohs(u16 val) {
  /* will be recognized by gcc into rotate insn and eventually rolw 8 */
  return (val << 8) | (val >> 8);
}

static inline u32 bpf_ntohl(u32 val) {
  /* gcc will use bswapsi2 insn */
  return __builtin_bswap32(val);
}

static inline u64 bpf_ntohll(u64 val) {
  /* gcc will use bswapdi2 insn */
  return __builtin_bswap64(val);
}

static inline unsigned __int128 bpf_ntoh128(unsigned __int128 val) {
  return (((unsigned __int128)bpf_ntohll(val) << 64) | (u64)bpf_ntohll(val >> 64));
}

static inline u16 bpf_htons(u16 val) {
  return bpf_ntohs(val);
}

static inline u32 bpf_htonl(u32 val) {
  return bpf_ntohl(val);
}
static inline u64 bpf_htonll(u64 val) {
  return bpf_ntohll(val);
}
static inline unsigned __int128 bpf_hton128(unsigned __int128 val) {
  return bpf_ntoh128(val);
}

static inline u64 load_dword(void *skb, u64 off) {
  return ((u64)load_word(skb, off) << 32) | load_word(skb, off + 4);
}

void bpf_store_byte(void *skb, u64 off, u64 val) asm("llvm.bpf.store.byte");
void bpf_store_half(void *skb, u64 off, u64 val) asm("llvm.bpf.store.half");
void bpf_store_word(void *skb, u64 off, u64 val) asm("llvm.bpf.store.word");
u64 bpf_pseudo_fd(u64, u64) asm("llvm.bpf.pseudo");
static inline void bpf_store_dword(void *skb, u64 off, u64 val) {
  bpf_store_word(skb, off, (u32)val);
  bpf_store_word(skb, off + 4, val >> 32);
}

#define MASK(_n) ((_n) < 64 ? (1ull << (_n)) - 1 : ((u64)-1LL))
#define MASK128(_n) ((_n) < 128 ? ((unsigned __int128)1 << (_n)) - 1 : ((unsigned __int128)-1))

static unsigned int bpf_log2(unsigned int v)
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

static unsigned int bpf_log2l(unsigned long v)
{
  unsigned int hi = v >> 32;
  if (hi)
    return bpf_log2(hi) + 32 + 1;
  else
    return bpf_log2(v) + 1;
}

struct bpf_context;

static inline __attribute__((always_inline))
SEC("helpers")
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
SEC("helpers")
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
SEC("helpers")
void * bpf_map_lookup_elem_(uintptr_t map, void *key) {
  return bpf_map_lookup_elem((void *)map, key);
}

static inline __attribute__((always_inline))
SEC("helpers")
int bpf_map_update_elem_(uintptr_t map, void *key, void *value, u64 flags) {
  return bpf_map_update_elem((void *)map, key, value, flags);
}

static inline __attribute__((always_inline))
SEC("helpers")
int bpf_map_delete_elem_(uintptr_t map, void *key) {
  return bpf_map_delete_elem((void *)map, key);
}

static inline __attribute__((always_inline))
SEC("helpers")
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
SEC("helpers")
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

#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))

#endif
