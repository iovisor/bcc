/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#pragma once

#include <sys/types.h>
#include <cstdint>
#include <string>
#include <vector>

#define PYTHON_STACK_FRAMES_PER_PROG 25
#define PYTHON_STACK_PROG_CNT 3
#define STACK_MAX_LEN (PYTHON_STACK_FRAMES_PER_PROG * PYTHON_STACK_PROG_CNT)
#define CLASS_NAME_LEN 32
#define FUNCTION_NAME_LEN 64
#define FILE_NAME_LEN 128
#define TASK_COMM_LEN 16

namespace ebpf {
namespace pyperf {

enum {
  STACK_STATUS_COMPLETE = 0,
  STACK_STATUS_ERROR = 1,
  STACK_STATUS_TRUNCATED = 2,
};

enum {
  GIL_STATE_NO_INFO = 0,
  GIL_STATE_ERROR = 1,
  GIL_STATE_UNINITIALIZED = 2,
  GIL_STATE_NOT_LOCKED = 3,
  GIL_STATE_THIS_THREAD = 4,
  GIL_STATE_GLOBAL_CURRENT_THREAD = 5,
  GIL_STATE_OTHER_THREAD = 6,
  GIL_STATE_NULL = 7,
};

enum {
  THREAD_STATE_UNKNOWN = 0,
  THREAD_STATE_MATCH = 1,
  THREAD_STATE_MISMATCH = 2,
  THREAD_STATE_THIS_THREAD_NULL = 3,
  THREAD_STATE_GLOBAL_CURRENT_THREAD_NULL = 4,
  THREAD_STATE_BOTH_NULL = 5,
};

enum {
  PTHREAD_ID_UNKNOWN = 0,
  PTHREAD_ID_MATCH = 1,
  PTHREAD_ID_MISMATCH = 2,
  PTHREAD_ID_THREAD_STATE_NULL = 3,
  PTHREAD_ID_NULL = 4,
  PTHREAD_ID_ERROR = 5,
};

typedef struct {
  int64_t PyObject_type;
  int64_t PyTypeObject_name;
  int64_t PyThreadState_frame;
  int64_t PyThreadState_thread;
  int64_t PyFrameObject_back;
  int64_t PyFrameObject_code;
  int64_t PyFrameObject_lineno;
  int64_t PyFrameObject_localsplus;
  int64_t PyCodeObject_filename;
  int64_t PyCodeObject_name;
  int64_t PyCodeObject_varnames;
  int64_t PyTupleObject_item;
  int64_t String_data;
  int64_t String_size;
} OffsetConfig;

typedef struct {
  uintptr_t current_state_addr;  // virtual address of _PyThreadState_Current
  uintptr_t tls_key_addr;     // virtual address of autoTLSkey for pthreads TLS
  uintptr_t gil_locked_addr;  // virtual address of gil_locked
  uintptr_t gil_last_holder_addr;  // virtual address of gil_last_holder
  OffsetConfig offsets;
} PidData;

typedef struct {
  char classname[CLASS_NAME_LEN];
  char name[FUNCTION_NAME_LEN];
  char file[FILE_NAME_LEN];
  // NOTE: PyFrameObject also has line number but it is typically just the
  // first line of that function and PyCode_Addr2Line needs to be called
  // to get the actual line
} Symbol;

typedef struct {
  uint32_t pid;
  uint32_t tid;
  char comm[TASK_COMM_LEN];
  uint8_t thread_state_match;
  uint8_t gil_state;
  uint8_t pthread_id_match;
  uint8_t stack_status;
  // instead of storing symbol name here directly, we add it to another
  // hashmap with Symbols and only store the ids here
  int64_t stack_len;
  int32_t stack[STACK_MAX_LEN];
} Event;

struct PyPerfSample {
  pid_t pid;
  pid_t tid;
  std::string comm;
  uint8_t threadStateMatch;
  uint8_t gilState;
  uint8_t pthreadIDMatch;
  uint8_t stackStatus;
  std::vector<int32_t> pyStackIds;

  explicit PyPerfSample(const Event* raw, int rawSize)
      : pid(raw->pid),
        tid(raw->tid),
        comm(raw->comm),
        threadStateMatch(raw->thread_state_match),
        gilState(raw->gil_state),
        pthreadIDMatch(raw->pthread_id_match),
        stackStatus(raw->stack_status),
        pyStackIds(raw->stack, raw->stack + raw->stack_len) {}
};

}  // namespace pyperf
}  // namespace ebpf
