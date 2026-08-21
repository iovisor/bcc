/*
 * Copyright (c) 2026 Bytedance, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include "bcc_dwarf_unwind.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <new>
#include <vector>

#ifdef HAVE_LIBGUNWINDER
extern "C" {
#include "gunwinder/unwinder.h"
}
#endif

struct bcc_dwarf_unwind_context {
#ifdef HAVE_LIBGUNWINDER
  struct gu_context *gu_ctx;
#endif
};

namespace {

const uint32_t kDefaultMaxFrames = 128;
const uint32_t kPublicMaxFrames = 512;

int set_errno_return(int err) {
  errno = err;
  return -err;
}

void free_frame(struct bcc_dwarf_unwind_frame *frame) {
  if (frame == nullptr)
    return;

  free(frame->symbol);
  free(frame->elf.base_name);
  free(frame->elf.elf_file_path);
  free(frame->elf.debug_file_path);
  free(frame->elf.build_id);
}

#ifdef HAVE_LIBGUNWINDER
#ifndef BCC_DWARF_UNWIND_TESTING
enum bcc_dwarf_unwind_stop_reason map_stop_reason(
    enum gu_unwind_reason reason) {
  switch (reason) {
  case GU_UNWIND_REASON_OK:
    return BCC_DWARF_UNWIND_REASON_OK;
  case GU_UNWIND_REASON_NO_REGS:
    return BCC_DWARF_UNWIND_REASON_NO_REGS;
  case GU_UNWIND_REASON_NO_ELF:
    return BCC_DWARF_UNWIND_REASON_NO_ELF;
  case GU_UNWIND_REASON_NO_CFI:
    return BCC_DWARF_UNWIND_REASON_NO_CFI;
  case GU_UNWIND_REASON_CFI_FAIL:
    return BCC_DWARF_UNWIND_REASON_CFI_FAIL;
  case GU_UNWIND_REASON_ARCH_FAIL:
    return BCC_DWARF_UNWIND_REASON_ARCH_FAIL;
  case GU_UNWIND_REASON_PROCESS_EXIT:
    return BCC_DWARF_UNWIND_REASON_PROCESS_EXIT;
  case GU_UNWIND_REASON_LANG_SKIP:
    return BCC_DWARF_UNWIND_REASON_LANG_SKIP;
  case GU_UNWIND_REASON_TRUNCATED:
    return BCC_DWARF_UNWIND_REASON_TRUNCATED;
  case GU_UNWIND_REASON_NO_EXEC_PC:
    return BCC_DWARF_UNWIND_REASON_NO_EXEC_PC;
  case GU_UNWIND_REASON_CFI_FRAME_DECODE_FAILED:
    return BCC_DWARF_UNWIND_REASON_CFI_FRAME_DECODE_FAILED;
  case GU_UNWIND_REASON_CFI_FRAME_CFA_FAILED:
    return BCC_DWARF_UNWIND_REASON_CFI_FRAME_CFA_FAILED;
  case GU_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED:
    return BCC_DWARF_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED;
  case GU_UNWIND_REASON_END_OF_STACK:
    return BCC_DWARF_UNWIND_REASON_END_OF_STACK;
  case GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE:
    return BCC_DWARF_UNWIND_REASON_STACK_READ_OUT_OF_RANGE;
  case GU_UNWIND_REASON_UNKNOWN:
  default:
    return BCC_DWARF_UNWIND_REASON_UNKNOWN;
  }
}
#endif

char *copy_string(const char *value) {
  if (value == nullptr)
    return nullptr;

  size_t len = strlen(value) + 1;
  char *copy = static_cast<char *>(malloc(len));
  if (copy == nullptr)
    return nullptr;

  memcpy(copy, value, len);
  return copy;
}

bool copy_elf_info(const struct gu_elf_info *src,
                   struct bcc_dwarf_unwind_elf *dst) {
  dst->size = sizeof(*dst);
  if (src == nullptr)
    return true;

  dst->base_name = copy_string(src->base_name);
  if (src->base_name != nullptr && dst->base_name == nullptr)
    return false;

  dst->elf_file_path = copy_string(src->elf_file_path);
  if (src->elf_file_path != nullptr && dst->elf_file_path == nullptr)
    return false;

  dst->debug_file_path = copy_string(src->debug_file_path);
  if (src->debug_file_path != nullptr && dst->debug_file_path == nullptr)
    return false;

  if (src->build_id != nullptr && src->build_id_len > 0) {
    dst->build_id = static_cast<uint8_t *>(malloc(src->build_id_len));
    if (dst->build_id == nullptr)
      return false;
    memcpy(dst->build_id, src->build_id, src->build_id_len);
    dst->build_id_len = src->build_id_len;
  }
  dst->golang = src->golang;
  return true;
}

struct frame_collection {
  std::vector<struct bcc_dwarf_unwind_frame> frames;
  size_t max_frames;
  bool failed;
  bool truncated;
};

void collect_frame(const struct gu_frame_record *src, void *user_ctx) {
  struct frame_collection *collection =
      static_cast<struct frame_collection *>(user_ctx);
  if (collection == nullptr || collection->failed)
    return;
  if (collection->frames.size() >= collection->max_frames) {
    collection->truncated = true;
    return;
  }

  struct bcc_dwarf_unwind_frame frame = {};
  frame.size = sizeof(frame);
  frame.flags = src->flags;
  frame.pc = src->pc;
  frame.abs_pc = src->abs_pc;
  frame.offset = src->offset;
  frame.symbol = copy_string(src->symbol);
  if (src->symbol != nullptr && frame.symbol == nullptr) {
    collection->failed = true;
    return;
  }

  if (!copy_elf_info(src->elf_info, &frame.elf)) {
    free_frame(&frame);
    collection->failed = true;
    return;
  }

  try {
    collection->frames.push_back(frame);
  } catch (...) {
    free_frame(&frame);
    collection->failed = true;
  }
}

#ifndef BCC_DWARF_UNWIND_TESTING
bool sample_has_malformed_stack(const struct bcc_dwarf_unwind_sample *sample) {
  return (sample->stack_data == nullptr && sample->stack_size != 0) ||
         (sample->stack_data != nullptr && sample->stack_size == 0);
}

bool sample_has_malformed_ustack_fp(
    const struct bcc_dwarf_unwind_sample *sample) {
  return (sample->ustack_fp == nullptr && sample->ustack_fp_level != 0) ||
         (sample->ustack_fp != nullptr && sample->ustack_fp_level == 0) ||
         sample->ustack_fp_level > MAX_FP_STACK_LEVEL + 1;
}

bool gu_regs_sample_valid(const struct gu_regs *regs) {
  return regs != nullptr && regs->size == sizeof(*regs) &&
         regs->version == GU_REGS_VERSION;
}
#endif

struct bcc_dwarf_unwind_result *build_result(
    const struct frame_collection &collection, int unwind_ret,
    enum bcc_dwarf_unwind_stop_reason reason) {
  struct bcc_dwarf_unwind_result *new_result =
      static_cast<struct bcc_dwarf_unwind_result *>(
          calloc(1, sizeof(*new_result)));
  if (new_result == nullptr)
    return nullptr;

  new_result->size = sizeof(*new_result);
  new_result->unwind_ret = unwind_ret;
  new_result->stop_reason = collection.truncated
                                ? BCC_DWARF_UNWIND_REASON_FRAME_LIMIT
                                : reason;
  new_result->frame_count = collection.frames.size();

  if (new_result->frame_count == 0)
    return new_result;

  new_result->frames = static_cast<struct bcc_dwarf_unwind_frame *>(
      calloc(new_result->frame_count, sizeof(*new_result->frames)));
  if (new_result->frames == nullptr) {
    free(new_result);
    return nullptr;
  }

  memcpy(new_result->frames, collection.frames.data(),
         new_result->frame_count * sizeof(*new_result->frames));
  return new_result;
}

#endif

}  // namespace

#ifdef BCC_DWARF_UNWIND_TESTING
#ifdef HAVE_LIBGUNWINDER
extern "C" int bcc_dwarf_unwind_internal_test_build_result(
    const struct gu_frame_record *frames, size_t frame_count,
    size_t max_frames, enum bcc_dwarf_unwind_stop_reason stop_reason,
    struct bcc_dwarf_unwind_result **result) {
  if (result == nullptr)
    return set_errno_return(EINVAL);

  *result = nullptr;
  struct frame_collection collection = {};
  collection.max_frames = max_frames;

  for (size_t i = 0; i < frame_count; ++i)
    collect_frame(&frames[i], &collection);

  if (collection.failed) {
    for (auto &frame : collection.frames)
      free_frame(&frame);
    return set_errno_return(ENOMEM);
  }

  struct bcc_dwarf_unwind_result *new_result =
      build_result(collection, 0, stop_reason);
  if (new_result == nullptr) {
    for (auto &frame : collection.frames)
      free_frame(&frame);
    return set_errno_return(ENOMEM);
  }

  *result = new_result;
  return 0;
}
#endif
#else
extern "C" {

bool bcc_dwarf_unwind_supported(void) {
#ifdef HAVE_LIBGUNWINDER
  return true;
#else
  return false;
#endif
}

int bcc_dwarf_unwind_context_new(
    const struct bcc_dwarf_unwind_options *options,
    struct bcc_dwarf_unwind_context **context) {
  if (context == nullptr)
    return set_errno_return(EINVAL);

  *context = nullptr;
  if (options != nullptr && options->size < sizeof(*options))
    return set_errno_return(EINVAL);

  struct bcc_dwarf_unwind_context *new_context =
      new (std::nothrow) bcc_dwarf_unwind_context();
  if (new_context == nullptr)
    return set_errno_return(ENOMEM);

#ifdef HAVE_LIBGUNWINDER
  struct gu_init_cfg cfg = {};
  new_context->gu_ctx = gu_init(&cfg);
  if (new_context->gu_ctx == nullptr) {
    delete new_context;
    return set_errno_return(errno != 0 ? errno : ENOMEM);
  }
#endif

  *context = new_context;
  return 0;
}

void bcc_dwarf_unwind_context_free(struct bcc_dwarf_unwind_context *context) {
  if (context == nullptr)
    return;

#ifdef HAVE_LIBGUNWINDER
  gu_cleanup(context->gu_ctx);
#endif
  delete context;
}

int bcc_dwarf_unwind_sample(struct bcc_dwarf_unwind_context *context,
                            const struct bcc_dwarf_unwind_sample *sample,
                            struct bcc_dwarf_unwind_result **result) {
  if (result == nullptr)
    return set_errno_return(EINVAL);

  *result = nullptr;
  if (context == nullptr || sample == nullptr ||
      sample->size < sizeof(*sample))
    return set_errno_return(EINVAL);

#ifndef HAVE_LIBGUNWINDER
  return set_errno_return(ENOTSUP);
#else
  if (sample->pid <= 0 || sample->regs == nullptr ||
      sample_has_malformed_stack(sample) ||
      sample_has_malformed_ustack_fp(sample))
    return set_errno_return(EINVAL);

  const struct gu_regs *caller_regs =
      static_cast<const struct gu_regs *>(sample->regs);
  if (!gu_regs_sample_valid(caller_regs))
    return set_errno_return(EINVAL);

  uint32_t max_frames = sample->max_frames == 0 ? kDefaultMaxFrames
                                                : sample->max_frames;
  max_frames = std::min(max_frames, kPublicMaxFrames);

  struct gu_regs regs = *caller_regs;
  struct gu_stack_info info = {};
  info.pid = sample->pid;
  info.stack_size = sample->stack_size;
  info.unique_id = sample->unique_id;
  info.stack_data = const_cast<uint8_t *>(sample->stack_data);
  gu_stack_info_set_regs(&info, &regs);

  if (sample->ustack_fp_level > 0) {
    memcpy(info.ustack_fp, sample->ustack_fp,
           sample->ustack_fp_level * sizeof(info.ustack_fp[0]));
    info.ustack_fp_level = sample->ustack_fp_level;
    gu_flags_set(&info, GU_FLAG_HINT_SET_FP);
  }

  struct frame_collection collection = {};
  collection.max_frames = max_frames;

  int unwind_ret = gu_unwind(context->gu_ctx, &info, collect_frame,
                             &collection);
  if (collection.failed) {
    for (auto &frame : collection.frames)
      free_frame(&frame);
    return set_errno_return(ENOMEM);
  }

  enum bcc_dwarf_unwind_stop_reason reason =
      map_stop_reason(gu_flags_reason(info.flags));
  struct bcc_dwarf_unwind_result *new_result =
      build_result(collection, unwind_ret, reason);
  if (new_result == nullptr) {
    for (auto &frame : collection.frames)
      free_frame(&frame);
    return set_errno_return(ENOMEM);
  }

  *result = new_result;
  return 0;
#endif
}

void bcc_dwarf_unwind_result_free(struct bcc_dwarf_unwind_result *result) {
  if (result == nullptr)
    return;

  for (size_t i = 0; i < result->frame_count; ++i)
    free_frame(&result->frames[i]);
  free(result->frames);
  free(result);
}

}
#endif
