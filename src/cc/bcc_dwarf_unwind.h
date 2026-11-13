/*
 * Copyright (c) 2026 Bytedance, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#ifndef BCC_DWARF_UNWIND_H
#define BCC_DWARF_UNWIND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bcc_dwarf_unwind_context;
struct bcc_dwarf_unwind_result;

struct bcc_dwarf_unwind_options {
  uint32_t size;
  uint32_t flags;
};

struct bcc_dwarf_unwind_sample {
  uint32_t size;
  uint32_t flags;
  pid_t pid;
  uint64_t unique_id;
  /*
   * Publicly documented as a pointer to const struct gu_regs from
   * gunwinder/unwinder_types.h. This remains an opaque pointer so libbcc
   * headers do not require libgunwinder headers when DWARF unwinding is off.
   */
  const void *regs;
  const uint8_t *stack_data;
  size_t stack_size;
  const uint64_t *ustack_fp;
  uint64_t ustack_fp_level;
  uint32_t max_frames;
};

enum bcc_dwarf_unwind_stop_reason {
  BCC_DWARF_UNWIND_REASON_OK = 0,
  BCC_DWARF_UNWIND_REASON_NO_REGS = 1,
  BCC_DWARF_UNWIND_REASON_NO_ELF = 2,
  BCC_DWARF_UNWIND_REASON_NO_CFI = 3,
  BCC_DWARF_UNWIND_REASON_CFI_FAIL = 4,
  BCC_DWARF_UNWIND_REASON_ARCH_FAIL = 5,
  BCC_DWARF_UNWIND_REASON_PROCESS_EXIT = 6,
  BCC_DWARF_UNWIND_REASON_LANG_SKIP = 7,
  BCC_DWARF_UNWIND_REASON_TRUNCATED = 8,
  BCC_DWARF_UNWIND_REASON_NO_EXEC_PC = 9,
  BCC_DWARF_UNWIND_REASON_CFI_FRAME_DECODE_FAILED = 10,
  BCC_DWARF_UNWIND_REASON_CFI_FRAME_CFA_FAILED = 11,
  BCC_DWARF_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED = 12,
  BCC_DWARF_UNWIND_REASON_END_OF_STACK = 13,
  BCC_DWARF_UNWIND_REASON_STACK_READ_OUT_OF_RANGE = 14,
  /*
   * BCC copied only the first max_frames callbacks from libgunwinder.
   * This is separate from BCC_DWARF_UNWIND_REASON_TRUNCATED, which maps
   * libgunwinder's stack-data truncation stop reason.
   */
  BCC_DWARF_UNWIND_REASON_FRAME_LIMIT = 15,
  BCC_DWARF_UNWIND_REASON_UNKNOWN = 0xff,
};

struct bcc_dwarf_unwind_elf {
  uint32_t size;
  char *base_name;
  char *elf_file_path;
  char *debug_file_path;
  uint8_t *build_id;
  size_t build_id_len;
  bool golang;
};

struct bcc_dwarf_unwind_frame {
  uint32_t size;
  uint32_t flags;
  uint64_t pc;
  uint64_t abs_pc;
  uint64_t offset;
  char *symbol;
  struct bcc_dwarf_unwind_elf elf;
};

struct bcc_dwarf_unwind_result {
  uint32_t size;
  int unwind_ret;
  enum bcc_dwarf_unwind_stop_reason stop_reason;
  size_t frame_count;
  struct bcc_dwarf_unwind_frame *frames;
};

bool bcc_dwarf_unwind_supported(void);
int bcc_dwarf_unwind_context_new(
    const struct bcc_dwarf_unwind_options *options,
    struct bcc_dwarf_unwind_context **context);
void bcc_dwarf_unwind_context_free(struct bcc_dwarf_unwind_context *context);
int bcc_dwarf_unwind_sample(struct bcc_dwarf_unwind_context *context,
                            const struct bcc_dwarf_unwind_sample *sample,
                            struct bcc_dwarf_unwind_result **result);
void bcc_dwarf_unwind_result_free(struct bcc_dwarf_unwind_result *result);

#ifdef __cplusplus
}
#endif

#endif
