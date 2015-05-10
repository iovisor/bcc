/*
 * ====================================================================
 * Copyright (c) 2012-2013, PLUMgrid, http://plumgrid.com
 *
 * This source is subject to the PLUMgrid License.
 * All rights reserved.
 *
 * THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * PLUMgrid confidential information, delete if you are not the
 * intended recipient.
 *
 * ====================================================================
 */

#include <linux/skbuff.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#define assert(v)

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
  return ((u64)load_word(skb, off) << 4) | load_word(skb, off + 4);
}

void bpf_store_byte(void *skb, u64 off, u64 val) asm("llvm.bpf.store.byte");
void bpf_store_half(void *skb, u64 off, u64 val) asm("llvm.bpf.store.half");
void bpf_store_word(void *skb, u64 off, u64 val) asm("llvm.bpf.store.word");
static inline void bpf_store_dword(void *skb, u64 off, u64 val) {
  bpf_store_word(skb, off, (u32)val);
  bpf_store_word(skb, off + 4, val >> 32);
}

#define MASK(_n) ((_n) < 64 ? (1ull << (_n)) - 1 : ((u64)-1LL))
#define MASK128(_n) ((_n) < 128 ? ((unsigned __int128)1 << (_n)) - 1 : ((unsigned __int128)-1))

struct _skbuff;
struct bpf_context;

//static inline __attribute__((always_inline))
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
  } else if (bofs + bsz <= 64) {
    return bpf_ntohll(load_dword(pkt, off)) >> (64 - (bofs + bsz))  &  MASK(bsz);
  } else {
    assert(0);
  }
  return 0;
}

//static inline __attribute__((always_inline))
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
  } else if (bofs + bsz <= 128) {
    assert(0);
    //bpf_store_16bytes(pkt, off, bpf_hton128(~(MASK128(bsz) << (128 - (bofs + bsz)))),
    //                 bpf_hton128((val & MASK128(bsz)) << (128 - (bofs + bsz))));
  } else {
    assert(0);
  }
}

SEC("helpers")
void * bpf_map_lookup_elem_(uintptr_t map, void *key) {
  return bpf_map_lookup_elem((void *)map, key);
}

SEC("helpers")
int bpf_map_update_elem_(uintptr_t map, void *key, void *value, u64 flags) {
  return bpf_map_update_elem((void *)map, key, value, flags);
}

SEC("helpers")
int bpf_map_delete_elem_(uintptr_t map, void *key) {
  return bpf_map_delete_elem((void *)map, key);
}

SEC("helpers")
int bpf_skb_store_bytes_(void *ctx, u64 off, void *from, u64 len, u64 flags) {
  return bpf_skb_store_bytes(ctx, off, from, len, flags);
}

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

#undef assert

