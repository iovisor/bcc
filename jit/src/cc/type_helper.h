/*
 * ====================================================================
 * Copyright (c) 2012, PLUMgrid, http://plumgrid.com
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

#pragma once

namespace ebpf {
namespace cc {

// Represent the numeric type of a protocol field
enum FieldType {
  INVALID = 0,
  UINT8_T,
  UINT16_T,
  UINT32_T,
  UINT64_T,
  UINT128_T,
  VOID
};

static inline size_t enum_to_size(const FieldType t) {
  switch (t) {
    case UINT8_T: return sizeof(uint8_t);
    case UINT16_T: return sizeof(uint16_t);
    case UINT32_T: return sizeof(uint32_t);
    case UINT64_T: return sizeof(uint64_t);
    case UINT128_T: return sizeof(__uint128_t);
    default:
      return 0;
  }
}

/// Convert a bit size to the next highest power of 2
static inline int next_base2(int v) {
  --v;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  ++v;
  return v;
}

static inline const char* bits_to_uint(int v) {
  v = next_base2(v);
  if (v <= 8) {
    return "uint8_t";
  } else if (v == 16) {
    return "uint16_t";
  } else if (v == 32) {
    return "uint32_t";
  } else if (v == 64) {
    return "uint64_t";
  } else if (v >= 128) {
    /* in plumlet 128-bit integers should be 8-byte aligned,
     * all other ints should have natural alignment */
    return "unsigned __int128 __attribute__((packed, aligned(8)))";
  }
  return "void";
}

static inline FieldType bits_to_enum(int v) {
  v = next_base2(v);
  if (v <= 8) {
    return UINT8_T;
  } else if (v == 16) {
    return UINT16_T;
  } else if (v == 32) {
    return UINT32_T;
  } else if (v == 64) {
    return UINT64_T;
  } else if (v >= 128) {
    return UINT128_T;
  }
  return VOID;
}

static inline size_t bits_to_size(int v) {
  return enum_to_size(bits_to_enum(v));
}

static inline size_t align_offset(size_t offset, FieldType ft) {
  switch (ft) {
    case UINT8_T:
      return offset % 8 > 0 ? offset + (8 - offset % 8) : offset;
    case UINT16_T:
      return offset % 16 > 0 ? offset + (16 - offset % 16) : offset;
    case UINT32_T:
      return offset % 32 > 0 ? offset + (32 - offset % 32) : offset;
    case UINT64_T:
    case UINT128_T:
      return offset % 64 > 0 ? offset + (64 - offset % 64) : offset;
    default:
      ;
  }
  return offset;
}

}  // namespace cc
}  // namespace ebpf
