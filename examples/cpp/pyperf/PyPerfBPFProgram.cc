/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <string>

namespace ebpf {
namespace pyperf {

extern const std::string PYPERF_BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#define PYTHON_STACK_FRAMES_PER_PROG 25
#define PYTHON_STACK_PROG_CNT 3
#define STACK_MAX_LEN (PYTHON_STACK_FRAMES_PER_PROG * PYTHON_STACK_PROG_CNT)
#define CLASS_NAME_LEN 32
#define FUNCTION_NAME_LEN 64
#define FILE_NAME_LEN 128
#define TASK_COMM_LEN 16

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
  uintptr_t current_state_addr; // virtual address of _PyThreadState_Current
  uintptr_t tls_key_addr; // virtual address of autoTLSkey for pthreads TLS
  uintptr_t gil_locked_addr; // virtual address of gil_locked
  uintptr_t gil_last_holder_addr; // virtual address of gil_last_holder
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

#define _STR_CONCAT(str1, str2) str1##str2
#define STR_CONCAT(str1, str2) _STR_CONCAT(str1, str2)
#define FAIL_COMPILATION_IF(condition)            \
  typedef struct {                                \
    char _condition_check[1 - 2 * !!(condition)]; \
  } STR_CONCAT(compile_time_condition_check, __COUNTER__);
// See comments in get_frame_data
FAIL_COMPILATION_IF(sizeof(Symbol) == sizeof(struct bpf_perf_event_value))

typedef struct {
  OffsetConfig offsets;
  uint64_t cur_cpu;
  int64_t symbol_counter;
  void* frame_ptr;
  int64_t python_stack_prog_call_cnt;
  Event event;
} sample_state_t;

BPF_PERCPU_ARRAY(state_heap, sample_state_t, 1);
BPF_HASH(symbols, Symbol, int32_t, __SYMBOLS_SIZE__);
BPF_HASH(pid_config, pid_t, PidData);
BPF_PROG_ARRAY(progs, 1);

BPF_PERF_OUTPUT(events);

static inline __attribute__((__always_inline__)) void* get_thread_state(
    void* tls_base,
    PidData* pid_data) {
  // Python sets the thread_state using pthread_setspecific with the key
  // stored in a global variable autoTLSkey.
  // We read the value of the key from the global variable and then read
  // the value in the thread-local storage. This relies on pthread implementation.
  // This is basically the same as running the following in GDB:
  //  p *(PyThreadState*)((struct pthread*)pthread_self())->
  //    specific_1stblock[autoTLSkey]->data
  int key;
  bpf_probe_read_user(&key, sizeof(key), (void*)pid_data->tls_key_addr);
  // This assumes autoTLSkey < 32, which means that the TLS is stored in
  //   pthread->specific_1stblock[autoTLSkey]
  // 0x310 is offsetof(struct pthread, specific_1stblock),
  // 0x10 is sizeof(pthread_key_data)
  // 0x8 is offsetof(struct pthread_key_data, data)
  // 'struct pthread' is not in the public API so we have to hardcode
  // the offsets here
  void* thread_state;
  bpf_probe_read_user(
      &thread_state,
      sizeof(thread_state),
      tls_base + 0x310 + key * 0x10 + 0x08);
  return thread_state;
}

static inline __attribute__((__always_inline__)) int submit_sample(
    struct pt_regs* ctx,
    sample_state_t* state) {
  events.perf_submit(ctx, &state->event, sizeof(Event));
  return 0;
}

// this function is trivial, but we need to do map lookup in separate function,
// because BCC doesn't allow direct map calls (including lookups) from inside
// a macro (which we want to do in GET_STATE() macro below)
static inline __attribute__((__always_inline__)) sample_state_t* get_state() {
  int zero = 0;
  return state_heap.lookup(&zero);
}

#define GET_STATE()                     \
  sample_state_t* state = get_state();  \
  if (!state) {                         \
    return 0; /* should never happen */ \
  }

static inline __attribute__((__always_inline__)) int get_thread_state_match(
    void* this_thread_state,
    void* global_thread_state) {
  if (this_thread_state == 0 && global_thread_state == 0) {
    return THREAD_STATE_BOTH_NULL;
  }
  if (this_thread_state == 0) {
    return THREAD_STATE_THIS_THREAD_NULL;
  }
  if (global_thread_state == 0) {
    return THREAD_STATE_GLOBAL_CURRENT_THREAD_NULL;
  }
  if (this_thread_state == global_thread_state) {
    return THREAD_STATE_MATCH;
  } else {
    return THREAD_STATE_MISMATCH;
  }
}

static inline __attribute__((__always_inline__)) int get_gil_state(
    void* this_thread_state,
    void* global_thread_state,
    PidData* pid_data) {
  // Get information of GIL state
  if (pid_data->gil_locked_addr == 0 || pid_data->gil_last_holder_addr == 0) {
    return GIL_STATE_NO_INFO;
  }

  int gil_locked = 0;
  void* gil_thread_state = 0;
  if (bpf_probe_read_user(
          &gil_locked, sizeof(gil_locked), (void*)pid_data->gil_locked_addr)) {
    return GIL_STATE_ERROR;
  }

  switch (gil_locked) {
    case -1:
      return GIL_STATE_UNINITIALIZED;
    case 0:
      return GIL_STATE_NOT_LOCKED;
    case 1:
      // GIL is held by some Thread
      bpf_probe_read_user(
          &gil_thread_state,
          sizeof(void*),
          (void*)pid_data->gil_last_holder_addr);
      if (gil_thread_state == this_thread_state) {
        return GIL_STATE_THIS_THREAD;
      } else if (gil_thread_state == global_thread_state) {
        return GIL_STATE_GLOBAL_CURRENT_THREAD;
      } else if (gil_thread_state == 0) {
        return GIL_STATE_NULL;
      } else {
        return GIL_STATE_OTHER_THREAD;
      }
    default:
      return GIL_STATE_ERROR;
  }
}

static inline __attribute__((__always_inline__)) int
get_pthread_id_match(void* thread_state, void* tls_base, PidData* pid_data) {
  if (thread_state == 0) {
    return PTHREAD_ID_THREAD_STATE_NULL;
  }

  uint64_t pthread_self, pthread_created;

  bpf_probe_read_user(
      &pthread_created,
      sizeof(pthread_created),
      thread_state + pid_data->offsets.PyThreadState_thread);
  if (pthread_created == 0) {
    return PTHREAD_ID_NULL;
  }

  // 0x10 = offsetof(struct pthread, header.self)
  bpf_probe_read_user(&pthread_self, sizeof(pthread_self), tls_base + 0x10);
  if (pthread_self == 0) {
    return PTHREAD_ID_ERROR;
  }

  if (pthread_self == pthread_created) {
    return PTHREAD_ID_MATCH;
  } else {
    return PTHREAD_ID_MISMATCH;
  }
}

int on_event(struct pt_regs* ctx) {
  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = (pid_t)(pid_tgid >> 32);
  PidData* pid_data = pid_config.lookup(&pid);
  if (!pid_data) {
    return 0;
  }

  GET_STATE();

  state->offsets = pid_data->offsets;
  state->cur_cpu = bpf_get_smp_processor_id();
  state->python_stack_prog_call_cnt = 0;

  Event* event = &state->event;
  event->pid = pid;
  event->tid = (pid_t)pid_tgid;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  // Get pointer of global PyThreadState, which should belong to the Thread
  // currently holds the GIL
  void* global_current_thread = (void*)0;
  bpf_probe_read_user(
      &global_current_thread,
      sizeof(global_current_thread),
      (void*)pid_data->current_state_addr);

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
#if __x86_64__
// thread_struct->fs was renamed to fsbase in
// https://github.com/torvalds/linux/commit/296f781a4b7801ad9c1c0219f9e87b6c25e196fe
// so depending on kernel version, we need to account for that
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
  void* tls_base = (void*)task->thread.fs;
#else
  void* tls_base = (void*)task->thread.fsbase;
#endif
#elif __aarch64__
  void* tls_base = (void*)task->thread.tp_value;
#else
#error "Unsupported platform"
#endif

  // Read PyThreadState of this Thread from TLS
  void* thread_state = get_thread_state(tls_base, pid_data);

  // Check for matching between TLS PyThreadState and
  // the global _PyThreadState_Current
  event->thread_state_match =
      get_thread_state_match(thread_state, global_current_thread);

  // Read GIL state
  event->gil_state =
      get_gil_state(thread_state, global_current_thread, pid_data);

  // Check for matching between pthread ID created current PyThreadState and
  // pthread of actual current pthread
  event->pthread_id_match =
      get_pthread_id_match(thread_state, tls_base, pid_data);

  // pre-initialize event struct in case any subprogram below fails
  event->stack_status = STACK_STATUS_COMPLETE;
  event->stack_len = 0;

  if (thread_state != 0) {
    // Get pointer to top frame from PyThreadState
    bpf_probe_read_user(
        &state->frame_ptr,
        sizeof(void*),
        thread_state + pid_data->offsets.PyThreadState_frame);
    // jump to reading first set of Python frames
    progs.call(ctx, PYTHON_STACK_PROG_IDX);
    // we won't ever get here
  }

  return submit_sample(ctx, state);
}

static inline __attribute__((__always_inline__)) void get_names(
    void* cur_frame,
    void* code_ptr,
    OffsetConfig* offsets,
    Symbol* symbol,
    void* ctx) {
  // Figure out if we want to parse class name, basically checking the name of
  // the first argument,
  //   ((PyTupleObject*)$frame->f_code->co_varnames)->ob_item[0]
  // If it's 'self', we get the type and it's name, if it's cls, we just get
  // the name. This is not perfect but there is no better way to figure this
  // out from the code object.
  void* args_ptr;
  bpf_probe_read_user(
      &args_ptr, sizeof(void*), code_ptr + offsets->PyCodeObject_varnames);
  bpf_probe_read_user(
      &args_ptr, sizeof(void*), args_ptr + offsets->PyTupleObject_item);
  bpf_probe_read_user_str(
      &symbol->name, sizeof(symbol->name), args_ptr + offsets->String_data);

  // compare strings as ints to save instructions
  char self_str[4] = {'s', 'e', 'l', 'f'};
  char cls_str[4] = {'c', 'l', 's', '\0'};
  bool first_self = *(int32_t*)symbol->name == *(int32_t*)self_str;
  bool first_cls = *(int32_t*)symbol->name == *(int32_t*)cls_str;

  // We re-use the same Symbol instance across loop iterations, which means
  // we will have left-over data in the struct. Although this won't affect
  // correctness of the result because we have '\0' at end of the strings read,
  // it would affect effectiveness of the deduplication.
  // Helper bpf_perf_prog_read_value clears the buffer on error, so here we
  // (ab)use this behavior to clear the memory. It requires the size of Symbol
  // to be different from struct bpf_perf_event_value, which we check at
  // compilation time using the FAIL_COMPILATION_IF macro.
  bpf_perf_prog_read_value(ctx, symbol, sizeof(Symbol));

  // Read class name from $frame->f_localsplus[0]->ob_type->tp_name.
  if (first_self || first_cls) {
    void* ptr;
    bpf_probe_read_user(
        &ptr, sizeof(void*), cur_frame + offsets->PyFrameObject_localsplus);
    if (first_self) {
      // we are working with an instance, first we need to get type
      bpf_probe_read_user(&ptr, sizeof(void*), ptr + offsets->PyObject_type);
    }
    bpf_probe_read_user(&ptr, sizeof(void*), ptr + offsets->PyTypeObject_name);
    bpf_probe_read_user_str(&symbol->classname, sizeof(symbol->classname), ptr);
  }

  void* pystr_ptr;
  // read PyCodeObject's filename into symbol
  bpf_probe_read_user(
      &pystr_ptr, sizeof(void*), code_ptr + offsets->PyCodeObject_filename);
  bpf_probe_read_user_str(
      &symbol->file, sizeof(symbol->file), pystr_ptr + offsets->String_data);
  // read PyCodeObject's name into symbol
  bpf_probe_read_user(
      &pystr_ptr, sizeof(void*), code_ptr + offsets->PyCodeObject_name);
  bpf_probe_read_user_str(
      &symbol->name, sizeof(symbol->name), pystr_ptr + offsets->String_data);
}

// get_frame_data reads current PyFrameObject filename/name and updates
// stack_info->frame_ptr with pointer to next PyFrameObject
static inline __attribute__((__always_inline__)) bool get_frame_data(
    void** frame_ptr,
    OffsetConfig* offsets,
    Symbol* symbol,
    // ctx is only used to call helper to clear symbol, see documentation below
    void* ctx) {
  void* cur_frame = *frame_ptr;
  if (!cur_frame) {
    return false;
  }
  void* code_ptr;
  // read PyCodeObject first, if that fails, then no point reading next frame
  bpf_probe_read_user(
      &code_ptr, sizeof(void*), cur_frame + offsets->PyFrameObject_code);
  if (!code_ptr) {
    return false;
  }

  get_names(cur_frame, code_ptr, offsets, symbol, ctx);

  // read next PyFrameObject pointer, update in place
  bpf_probe_read_user(
      frame_ptr, sizeof(void*), cur_frame + offsets->PyFrameObject_back);

  return true;
}

// To avoid duplicate ids, every CPU needs to use different ids when inserting
// into the hashmap. NUM_CPUS is defined at PyPerf backend side and passed
// through CFlag.
static inline __attribute__((__always_inline__)) int64_t get_symbol_id(
    sample_state_t* state,
    Symbol* sym) {
  int32_t* symbol_id_ptr = symbols.lookup(sym);
  if (symbol_id_ptr) {
    return *symbol_id_ptr;
  }
  // the symbol is new, bump the counter
  int32_t symbol_id = state->symbol_counter * NUM_CPUS + state->cur_cpu;
  state->symbol_counter++;
  symbols.update(sym, &symbol_id);
  return symbol_id;
}

int read_python_stack(struct pt_regs* ctx) {
  GET_STATE();

  state->python_stack_prog_call_cnt++;
  Event* sample = &state->event;

  Symbol sym = {};
  bool last_res = false;
#pragma unroll
  for (int i = 0; i < PYTHON_STACK_FRAMES_PER_PROG; i++) {
    last_res = get_frame_data(&state->frame_ptr, &state->offsets, &sym, ctx);
    if (last_res) {
      uint32_t symbol_id = get_symbol_id(state, &sym);
      int64_t cur_len = sample->stack_len;
      if (cur_len >= 0 && cur_len < STACK_MAX_LEN) {
        sample->stack[cur_len] = symbol_id;
        sample->stack_len++;
      }
    }
  }

  if (!state->frame_ptr) {
    sample->stack_status = STACK_STATUS_COMPLETE;
  } else {
    if (!last_res) {
      sample->stack_status = STACK_STATUS_ERROR;
    } else {
      sample->stack_status = STACK_STATUS_TRUNCATED;
    }
  }

  if (sample->stack_status == STACK_STATUS_TRUNCATED &&
      state->python_stack_prog_call_cnt < PYTHON_STACK_PROG_CNT) {
    // read next batch of frames
    progs.call(ctx, PYTHON_STACK_PROG_IDX);
  }

  return submit_sample(ctx, state);
}
)";

}
}  // namespace ebpf
