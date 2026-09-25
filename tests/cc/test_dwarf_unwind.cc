/*
 * Copyright (c) 2026 Bytedance, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bcc_dwarf_unwind.h"
#include "catch.hpp"

#ifdef HAVE_LIBGUNWINDER
extern "C" {
#include "gunwinder/unwinder.h"
}

extern "C" int bcc_dwarf_unwind_internal_test_build_result(
    const struct gu_frame_record *frames, size_t frame_count,
    size_t max_frames, enum bcc_dwarf_unwind_stop_reason stop_reason,
    struct bcc_dwarf_unwind_result **result);
#endif

TEST_CASE("DWARF unwind ABI reports build-time support state",
          "[dwarf_unwind]") {
  struct bcc_dwarf_unwind_context *ctx = nullptr;
  struct bcc_dwarf_unwind_result *result =
      reinterpret_cast<struct bcc_dwarf_unwind_result *>(0x1);
  struct bcc_dwarf_unwind_options options = {};
  struct bcc_dwarf_unwind_sample sample = {};
  uint8_t stack_data[64] = {};

  options.size = sizeof(options);
  sample.size = sizeof(sample);
  sample.pid = 1;
  sample.regs = nullptr;
  sample.stack_data = stack_data;
  sample.stack_size = sizeof(stack_data);

#ifdef HAVE_LIBGUNWINDER
  REQUIRE(bcc_dwarf_unwind_supported() == true);
#else
  REQUIRE(bcc_dwarf_unwind_supported() == false);
#endif
  REQUIRE(bcc_dwarf_unwind_context_new(&options, &ctx) == 0);
  REQUIRE(ctx != nullptr);

  errno = 0;
#ifdef HAVE_LIBGUNWINDER
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
#else
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == -ENOTSUP);
  REQUIRE(errno == ENOTSUP);
#endif
  REQUIRE(result == nullptr);

  bcc_dwarf_unwind_result_free(nullptr);
  bcc_dwarf_unwind_context_free(nullptr);
  bcc_dwarf_unwind_context_free(ctx);
}

TEST_CASE("DWARF unwind sample validates enabled adapter input",
          "[dwarf_unwind]") {
  struct bcc_dwarf_unwind_context *ctx = nullptr;
  struct bcc_dwarf_unwind_options options = {};
  struct bcc_dwarf_unwind_sample sample = {};
  struct bcc_dwarf_unwind_result *result = nullptr;
  uint8_t stack_data[64] = {};

  options.size = sizeof(options);
  sample.size = sizeof(sample);
  sample.pid = 1;
  sample.regs = reinterpret_cast<const void *>(0x1);
  sample.stack_data = stack_data;
  sample.stack_size = sizeof(stack_data);

  REQUIRE(bcc_dwarf_unwind_context_new(&options, &ctx) == 0);

  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, nullptr) == -EINVAL);
  REQUIRE(errno == EINVAL);

  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(nullptr, &sample, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
  REQUIRE(result == nullptr);

  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, nullptr, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
  REQUIRE(result == nullptr);

  sample.size = offsetof(struct bcc_dwarf_unwind_sample, regs);
  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
  REQUIRE(result == nullptr);
  sample.size = sizeof(sample);

#ifndef HAVE_LIBGUNWINDER
  bcc_dwarf_unwind_context_free(ctx);
  return;
#endif

  sample.pid = 0;
  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
  REQUIRE(result == nullptr);
  sample.pid = 1;

  sample.regs = nullptr;
  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
  REQUIRE(result == nullptr);
  sample.regs = reinterpret_cast<const void *>(0x1);

  sample.stack_data = nullptr;
  sample.stack_size = sizeof(stack_data);
  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
  REQUIRE(result == nullptr);
  sample.stack_data = stack_data;

  sample.ustack_fp = reinterpret_cast<const uint64_t *>(0x1);
  sample.ustack_fp_level = 0;
  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == -EINVAL);
  REQUIRE(errno == EINVAL);
  REQUIRE(result == nullptr);

  bcc_dwarf_unwind_context_free(ctx);
}

#ifdef HAVE_LIBGUNWINDER
TEST_CASE("DWARF unwind collector deep-copies frame metadata",
          "[dwarf_unwind]") {
  unsigned char build_id[] = {0x12, 0x34, 0x56};
  char symbol[] = "leaf";
  char base_name[] = "app";
  char elf_file_path[] = "/tmp/app";
  char debug_file_path[] = "/tmp/app.debug";
  struct gu_elf_info elf_info = {};
  struct gu_frame_record frame = {};
  struct bcc_dwarf_unwind_result *result = nullptr;

  elf_info.base_name = base_name;
  elf_info.elf_file_path = elf_file_path;
  elf_info.debug_file_path = debug_file_path;
  elf_info.build_id = build_id;
  elf_info.build_id_len = sizeof(build_id);
  elf_info.golang = true;

  frame.pc = 0x1000;
  frame.abs_pc = 0x7f0000001000;
  frame.offset = 0x20;
  frame.symbol = symbol;
  frame.elf_info = &elf_info;
  frame.flags = GU_FRAME_ANON_EXEC;

  REQUIRE(bcc_dwarf_unwind_internal_test_build_result(
              &frame, 1, 4, BCC_DWARF_UNWIND_REASON_END_OF_STACK,
              &result) == 0);
  REQUIRE(result != nullptr);
  REQUIRE(result->frame_count == 1);
  REQUIRE(result->stop_reason == BCC_DWARF_UNWIND_REASON_END_OF_STACK);

  symbol[0] = 'X';
  base_name[0] = 'X';
  elf_file_path[0] = 'X';
  debug_file_path[0] = 'X';
  build_id[0] = 0xff;

  REQUIRE(result->frames[0].size == sizeof(result->frames[0]));
  REQUIRE(result->frames[0].flags == GU_FRAME_ANON_EXEC);
  REQUIRE(result->frames[0].pc == 0x1000);
  REQUIRE(result->frames[0].abs_pc == 0x7f0000001000);
  REQUIRE(result->frames[0].offset == 0x20);
  REQUIRE(strcmp(result->frames[0].symbol, "leaf") == 0);
  REQUIRE(result->frames[0].symbol != symbol);
  REQUIRE(result->frames[0].elf.size == sizeof(result->frames[0].elf));
  REQUIRE(strcmp(result->frames[0].elf.base_name, "app") == 0);
  REQUIRE(result->frames[0].elf.base_name != base_name);
  REQUIRE(strcmp(result->frames[0].elf.elf_file_path, "/tmp/app") == 0);
  REQUIRE(result->frames[0].elf.elf_file_path != elf_file_path);
  REQUIRE(strcmp(result->frames[0].elf.debug_file_path,
                 "/tmp/app.debug") == 0);
  REQUIRE(result->frames[0].elf.debug_file_path != debug_file_path);
  REQUIRE(result->frames[0].elf.build_id_len == 3);
  REQUIRE(result->frames[0].elf.build_id != build_id);
  REQUIRE(result->frames[0].elf.build_id[0] == 0x12);
  REQUIRE(result->frames[0].elf.build_id[1] == 0x34);
  REQUIRE(result->frames[0].elf.build_id[2] == 0x56);
  REQUIRE(result->frames[0].elf.golang == true);

  bcc_dwarf_unwind_result_free(result);
}

TEST_CASE("DWARF unwind collector reports BCC frame cap truncation",
          "[dwarf_unwind]") {
  char first_symbol[] = "first";
  char second_symbol[] = "second";
  struct gu_frame_record frames[2] = {};
  struct bcc_dwarf_unwind_result *result = nullptr;

  frames[0].pc = 0x1000;
  frames[0].symbol = first_symbol;
  frames[1].pc = 0x2000;
  frames[1].symbol = second_symbol;

  REQUIRE(bcc_dwarf_unwind_internal_test_build_result(
              frames, 2, 1, BCC_DWARF_UNWIND_REASON_END_OF_STACK,
              &result) == 0);
  REQUIRE(result != nullptr);
  REQUIRE(result->frame_count == 1);
  REQUIRE(result->frames != nullptr);
  REQUIRE(result->frames[0].pc == 0x1000);
  REQUIRE(strcmp(result->frames[0].symbol, "first") == 0);
  REQUIRE(result->stop_reason == BCC_DWARF_UNWIND_REASON_FRAME_LIMIT);

  bcc_dwarf_unwind_result_free(result);
}

TEST_CASE("DWARF unwind enabled adapter returns libgunwinder result",
          "[dwarf_unwind]") {
  struct bcc_dwarf_unwind_context *ctx = nullptr;
  struct bcc_dwarf_unwind_options options = {};
  struct bcc_dwarf_unwind_sample sample = {};
  struct bcc_dwarf_unwind_result *result = nullptr;
  struct gu_regs regs;
  uint8_t stack_data[64] = {};

  options.size = sizeof(options);
  gu_regs_init(&regs, GU_ARCH_NATIVE);

  sample.size = sizeof(sample);
  sample.pid = 99999999;
  sample.regs = &regs;
  sample.stack_data = stack_data;
  sample.stack_size = sizeof(stack_data);
  sample.max_frames = 8;

  REQUIRE(bcc_dwarf_unwind_context_new(&options, &ctx) == 0);

  errno = 0;
  REQUIRE(bcc_dwarf_unwind_sample(ctx, &sample, &result) == 0);
  REQUIRE(result != nullptr);
  REQUIRE(result->size >= sizeof(*result));
  REQUIRE(result->frame_count == 0);
  REQUIRE(result->frames == nullptr);
  REQUIRE(result->unwind_ret < 0);
  REQUIRE(result->stop_reason ==
          BCC_DWARF_UNWIND_REASON_PROCESS_EXIT);

  bcc_dwarf_unwind_result_free(result);
  bcc_dwarf_unwind_context_free(ctx);
}
#endif
