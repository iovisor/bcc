# Copyright (c) 2026 Bytedance, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import errno
import os

DWARF_STACK_BYTES = 8192
DWARF_REG_COUNT = 17
DWARF_MISSED_STACK = "[Missed User Stack]"

_DWARF_SAMPLE_TEMPLATE = r'''
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

#define DWARF_STACK_BYTES __DWARF_STACK_BYTES__
#define DWARF_REG_COUNT __DWARF_REG_COUNT__

struct bcc_dwarf_sample {
    u32 stack_size;
    u32 _pad;
    u64 regs[DWARF_REG_COUNT];
    u64 valid_mask;
    u8 stack[DWARF_STACK_BYTES];
};

static __always_inline u64 bcc_dwarf_user_addr_limit(void) {
    u64 page_offset = PAGE_OFFSET;

#if defined(__identity_base)
    bpf_probe_read_kernel(&page_offset, sizeof(page_offset), &__identity_base);
#elif defined(__PAGE_OFFSET_BASE)
    page_offset = __PAGE_OFFSET_BASE;
#elif defined(__PAGE_OFFSET_BASE_L4)
    page_offset = __PAGE_OFFSET_BASE_L4;
#endif

    return page_offset;
}

static __always_inline int bcc_dwarf_is_user_addr(u64 addr) {
    return addr != 0 && addr < bcc_dwarf_user_addr_limit();
}

static __always_inline int bcc_dwarf_regs_user_mode(struct pt_regs *regs) {
#if defined(__x86_64__)
    return (regs->cs & 3) == 3;
#else
    return bcc_dwarf_is_user_addr(PT_REGS_IP(regs));
#endif
}

static __always_inline int bcc_dwarf_valid_user_regs(struct pt_regs *regs) {
    return bcc_dwarf_regs_user_mode(regs) &&
        bcc_dwarf_is_user_addr(PT_REGS_IP(regs)) &&
        bcc_dwarf_is_user_addr(PT_REGS_SP(regs));
}

static __always_inline void bcc_dwarf_regs_from_stack(struct pt_regs *regs,
                                                      struct bcc_dwarf_sample *sample) {
    sample->regs[0] = regs->ax;
    sample->regs[1] = regs->dx;
    sample->regs[2] = regs->cx;
    sample->regs[3] = regs->bx;
    sample->regs[4] = regs->si;
    sample->regs[5] = regs->di;
    sample->regs[6] = regs->bp;
    sample->regs[7] = PT_REGS_SP(regs);
    sample->regs[8] = regs->r8;
    sample->regs[9] = regs->r9;
    sample->regs[10] = regs->r10;
    sample->regs[11] = regs->r11;
    sample->regs[12] = regs->r12;
    sample->regs[13] = regs->r13;
    sample->regs[14] = regs->r14;
    sample->regs[15] = regs->r15;
    sample->regs[16] = PT_REGS_IP(regs);
    sample->valid_mask = (1ULL << DWARF_REG_COUNT) - 1;
}

static __always_inline void bcc_dwarf_copy_pt_regs(struct pt_regs *src,
                                                   struct pt_regs *regs) {
    regs->ax = src->ax;
    regs->dx = src->dx;
    regs->cx = src->cx;
    regs->bx = src->bx;
    regs->si = src->si;
    regs->di = src->di;
    regs->bp = src->bp;
    regs->sp = PT_REGS_SP(src);
    regs->r8 = src->r8;
    regs->r9 = src->r9;
    regs->r10 = src->r10;
    regs->r11 = src->r11;
    regs->r12 = src->r12;
    regs->r13 = src->r13;
    regs->r14 = src->r14;
    regs->r15 = src->r15;
    regs->ip = PT_REGS_IP(src);
    regs->cs = src->cs;
}

static __always_inline void bcc_dwarf_copy_ctx_regs(
        struct bpf_perf_event_data *ctx, struct pt_regs *regs) {
    bcc_dwarf_copy_pt_regs(&ctx->regs, regs);
}

static __always_inline int bcc_dwarf_fill_sample_from_regs(struct pt_regs *ctx,
        struct bcc_dwarf_sample *sample) {
    struct pt_regs *ctx_regs = ctx;
    struct pt_regs *task_regs_ptr;
    struct pt_regs regs = {};
    struct task_struct *task;
    u64 user_sp;
    u64 user_stack_base;

    if (bcc_dwarf_valid_user_regs(ctx_regs)) {
        bcc_dwarf_copy_pt_regs(ctx, &regs);
    } else {
        task = (struct task_struct *)bpf_get_current_task_btf();
        task_regs_ptr = (struct pt_regs *)bpf_task_pt_regs(task);

        if (task_regs_ptr == 0)
            return 0;

        if (bpf_probe_read_kernel(&regs, sizeof(regs), task_regs_ptr))
            return 0;
    }

    if (!bcc_dwarf_valid_user_regs(&regs))
        return 0;

    bcc_dwarf_regs_from_stack(&regs, sample);
    user_sp = PT_REGS_SP(&regs);
    user_stack_base = user_sp & ~(PAGE_SIZE - 1);

    /*
     * libgunwinder interprets stack snapshots relative to the page that
     * contains the raw user SP.  Keep the register SP unchanged, but capture
     * bytes from the page-aligned stack base so CFA-relative reads can resolve
     * addresses below and above the exact SP offset.
     */
    if (bpf_probe_read_user(sample->stack, PAGE_SIZE,
        (void *)user_stack_base) < 0)
        return 0;

    sample->stack_size = PAGE_SIZE;
    if (bpf_probe_read_user(sample->stack + PAGE_SIZE, PAGE_SIZE,
        (void *)(user_stack_base + PAGE_SIZE)) == 0)
        sample->stack_size += PAGE_SIZE;

    return 1;
}

static __always_inline int bcc_dwarf_fill_sample(
        struct bpf_perf_event_data *ctx, struct bcc_dwarf_sample *sample) {
    struct pt_regs regs = {};

    bcc_dwarf_copy_ctx_regs(ctx, &regs);
    return bcc_dwarf_fill_sample_from_regs(&regs, sample);
}
'''

_DWARF_PROFILE_TEMPLATE = _DWARF_SAMPLE_TEMPLATE + r'''

struct dwarf_event_t {
    u32 pid;
    u32 tid;
    u32 stack_size;
    u32 _pad;
    u64 regs[DWARF_REG_COUNT];
    u64 valid_mask;
    char name[TASK_COMM_LEN];
    u8 stack[DWARF_STACK_BYTES];
};
BPF_PERF_OUTPUT(dwarf_events);
BPF_PERCPU_ARRAY(dwarf_event_buf, struct dwarf_event_t, 1);

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 tgid = 0;
    u32 pid = 0;

    struct bpf_pidns_info ns = {};
    if (USE_PIDNS &&
        !bpf_get_ns_current_pid_tgid(PIDNS_DEV, PIDNS_INO, &ns, sizeof(struct bpf_pidns_info))) {
        tgid = ns.tgid;
        pid = ns.pid;
    } else {
        u64 id = bpf_get_current_pid_tgid();
        tgid = id >> 32;
        pid = id;
    }

    if (IDLE_FILTER)
        return 0;

    if (!(THREAD_FILTER))
        return 0;

    if (container_should_be_filtered()) {
        return 0;
    }

    u32 zero = 0;
    struct dwarf_event_t *event = dwarf_event_buf.lookup(&zero);
    if (event == 0)
        return 0;

    event->pid = tgid;
    event->tid = pid;
    event->_pad = 0;
    event->stack_size = 0;
    event->valid_mask = 0;
    bpf_get_current_comm(&event->name, sizeof(event->name));

    if (!bcc_dwarf_fill_sample(ctx,
        (struct bcc_dwarf_sample *)&event->stack_size))
        return 0;

    dwarf_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
'''

_TASK_PT_REGS_PROBE = r'''
#include <linux/sched.h>
int test_task_pt_regs(void *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    return !!bpf_task_pt_regs(task);
}
'''

from .libbcc import (
    BCC_DWARF_UNWIND_REASON_ARCH_FAIL,
    BCC_DWARF_UNWIND_REASON_CFI_FAIL,
    BCC_DWARF_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED,
    BCC_DWARF_UNWIND_REASON_CFI_FRAME_CFA_FAILED,
    BCC_DWARF_UNWIND_REASON_CFI_FRAME_DECODE_FAILED,
    BCC_DWARF_UNWIND_REASON_END_OF_STACK,
    BCC_DWARF_UNWIND_REASON_FRAME_LIMIT,
    BCC_DWARF_UNWIND_REASON_LANG_SKIP,
    BCC_DWARF_UNWIND_REASON_NO_CFI,
    BCC_DWARF_UNWIND_REASON_NO_ELF,
    BCC_DWARF_UNWIND_REASON_NO_EXEC_PC,
    BCC_DWARF_UNWIND_REASON_NO_REGS,
    BCC_DWARF_UNWIND_REASON_OK,
    BCC_DWARF_UNWIND_REASON_PROCESS_EXIT,
    BCC_DWARF_UNWIND_REASON_STACK_READ_OUT_OF_RANGE,
    BCC_DWARF_UNWIND_REASON_TRUNCATED,
    BCC_DWARF_UNWIND_REASON_UNKNOWN,
    GU_ARCH_ARM64,
    GU_ARCH_NATIVE,
    GU_ARCH_X86_64,
    GU_REGS_MAX_DWARF_REGS,
    GU_REGS_VERSION,
    bcc_dwarf_unwind_options,
    bcc_dwarf_unwind_result,
    bcc_dwarf_unwind_sample,
    gu_regs,
    lib,
)


class DwarfUnwindError(OSError):
    def __init__(self, err, operation):
        OSError.__init__(self, err, os.strerror(err), operation)


class GuRegs(gu_regs):
    def set(self, dwarf_regno, value):
        if dwarf_regno < 0 or dwarf_regno >= GU_REGS_MAX_DWARF_REGS:
            return False
        self.dwarf[dwarf_regno] = value
        self.valid_mask |= 1 << dwarf_regno
        return True

    def get(self, dwarf_regno):
        if dwarf_regno < 0 or dwarf_regno >= GU_REGS_MAX_DWARF_REGS:
            return None
        if (self.valid_mask & (1 << dwarf_regno)) == 0:
            return None
        return self.dwarf[dwarf_regno]


class DwarfUnwindElf(object):
    def __init__(self, base_name=None, elf_file_path=None,
                 debug_file_path=None, build_id=b"", golang=False):
        self.base_name = base_name
        self.elf_file_path = elf_file_path
        self.debug_file_path = debug_file_path
        self.build_id = build_id
        self.golang = golang


class DwarfUnwindFrame(object):
    def __init__(self, pc=0, abs_pc=0, offset=0, symbol=None, flags=0,
                 elf=None):
        self.pc = pc
        self.abs_pc = abs_pc
        self.offset = offset
        self.symbol = symbol
        self.flags = flags
        self.elf = elf if elf is not None else DwarfUnwindElf()


class DwarfUnwindResult(object):
    def __init__(self, unwind_ret=0, stop_reason=0, frames=None):
        self.unwind_ret = unwind_ret
        self.stop_reason = stop_reason
        self.frames = frames if frames is not None else []


class DwarfUnwinder(object):
    def __init__(self, flags=0):
        self._context = None
        options = bcc_dwarf_unwind_options()
        options.flags = flags
        context = ct.c_void_p()
        ret = lib.bcc_dwarf_unwind_context_new(ct.byref(options),
                                               ct.byref(context))
        if ret < 0:
            _raise_from_errno(ret, "bcc_dwarf_unwind_context_new")
        self._context = context

    @staticmethod
    def supported():
        return lib.bcc_dwarf_unwind_supported()

    def close(self):
        if self._context:
            lib.bcc_dwarf_unwind_context_free(self._context)
            self._context = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __del__(self):
        self.close()

    def sample(self, pid, regs, stack_data=None, unique_id=0, ustack_fp=None,
               max_frames=0, flags=0):
        if self._context is None:
            raise DwarfUnwindError(errno.EINVAL, "bcc_dwarf_unwind_sample")
        sample, keepalive = _build_sample(pid, regs, stack_data, unique_id,
                                          ustack_fp, max_frames, flags)
        result = ct.POINTER(bcc_dwarf_unwind_result)()
        ret = lib.bcc_dwarf_unwind_sample(self._context, ct.byref(sample),
                                          ct.byref(result))
        if ret < 0:
            _raise_from_errno(ret, "bcc_dwarf_unwind_sample")
        if not result:
            raise DwarfUnwindError(errno.EINVAL, "bcc_dwarf_unwind_sample")
        try:
            return _copy_result(result.contents)
        finally:
            lib.bcc_dwarf_unwind_result_free(result)


def _build_sample(pid, regs, stack_data, unique_id, ustack_fp, max_frames,
                  flags):
    if not isinstance(regs, gu_regs):
        raise TypeError("regs must be a GuRegs instance")

    keepalive = [regs]
    sample = bcc_dwarf_unwind_sample()
    sample.flags = flags
    sample.pid = pid
    sample.unique_id = unique_id
    sample.regs = ct.cast(ct.byref(regs), ct.c_void_p)
    sample.max_frames = max_frames

    if stack_data is not None:
        stack = (ct.c_uint8 * len(stack_data)).from_buffer_copy(stack_data)
        keepalive.append(stack)
        sample.stack_data = stack
        sample.stack_size = len(stack_data)

    if ustack_fp is not None:
        fp = (ct.c_uint64 * len(ustack_fp))(*ustack_fp)
        keepalive.append(fp)
        sample.ustack_fp = fp
        sample.ustack_fp_level = len(ustack_fp)

    return sample, keepalive


def _copy_result(result):
    frames = []
    for i in range(result.frame_count):
        frames.append(_copy_frame(result.frames[i]))
    return DwarfUnwindResult(result.unwind_ret, result.stop_reason, frames)


def _copy_frame(frame):
    elf = frame.elf
    build_id = b""
    if elf.build_id and elf.build_id_len:
        build_id = bytes(bytearray(elf.build_id[:elf.build_id_len]))

    return DwarfUnwindFrame(
        pc=frame.pc,
        abs_pc=frame.abs_pc,
        offset=frame.offset,
        symbol=_decode(frame.symbol),
        flags=frame.flags,
        elf=DwarfUnwindElf(
            base_name=_decode(elf.base_name),
            elf_file_path=_decode(elf.elf_file_path),
            debug_file_path=_decode(elf.debug_file_path),
            build_id=build_id,
            golang=elf.golang))


def _decode(value):
    if value is None:
        return None
    return value.decode("utf-8", "replace")


def _raise_from_errno(ret, operation):
    err = ct.get_errno()
    if err == 0 and ret < 0:
        err = -ret
    raise DwarfUnwindError(err, operation)


class _DwarfProfileSnippetProvider(object):
    has_bpf_task_pt_regs = None
    bpf_task_pt_regs_error = None

    @classmethod
    def probe_task_pt_regs_support(cls):
        if cls.has_bpf_task_pt_regs is not None:
            return cls.has_bpf_task_pt_regs

        try:
            from . import BPF
            bpf = BPF(text=_TASK_PT_REGS_PROBE)
            bpf.load_func("test_task_pt_regs", BPF.PERF_EVENT)
            cls.has_bpf_task_pt_regs = True
            cls.bpf_task_pt_regs_error = None
        except Exception as e:
            cls.has_bpf_task_pt_regs = False
            cls.bpf_task_pt_regs_error = str(e)
        return cls.has_bpf_task_pt_regs

    @classmethod
    def get_profile_bpf_text(cls, stack_bytes=DWARF_STACK_BYTES,
                            reg_count=DWARF_REG_COUNT,
                            force_bpf_task_pt_regs=None):
        if force_bpf_task_pt_regs is False:
            raise RuntimeError("DWARF profiling requires bpf_task_pt_regs")
        if force_bpf_task_pt_regs is None and not cls.probe_task_pt_regs_support():
            raise RuntimeError("DWARF profiling requires bpf_task_pt_regs")
        bpf_text = _DWARF_PROFILE_TEMPLATE
        replacements = {
            "__DWARF_STACK_BYTES__": str(stack_bytes),
            "__DWARF_REG_COUNT__": str(reg_count),
        }
        for marker, value in replacements.items():
            bpf_text = bpf_text.replace(marker, value)
        return bpf_text

    @classmethod
    def get_sample_bpf_text(cls, stack_bytes=DWARF_STACK_BYTES,
                            reg_count=DWARF_REG_COUNT,
                            force_bpf_task_pt_regs=None):
        if force_bpf_task_pt_regs is False:
            raise RuntimeError("DWARF stacks require bpf_task_pt_regs")
        if force_bpf_task_pt_regs is None and not cls.probe_task_pt_regs_support():
            raise RuntimeError("DWARF stacks require bpf_task_pt_regs")
        bpf_text = _DWARF_SAMPLE_TEMPLATE
        replacements = {
            "__DWARF_STACK_BYTES__": str(stack_bytes),
            "__DWARF_REG_COUNT__": str(reg_count),
        }
        for marker, value in replacements.items():
            bpf_text = bpf_text.replace(marker, value)
        return bpf_text


def build_dwarf_profile_bpf_text(stack_bytes=DWARF_STACK_BYTES,
                                reg_count=DWARF_REG_COUNT,
                                force_bpf_task_pt_regs=None):
    return _DwarfProfileSnippetProvider.get_profile_bpf_text(
        stack_bytes=stack_bytes,
        reg_count=reg_count,
        force_bpf_task_pt_regs=force_bpf_task_pt_regs)


def build_dwarf_sample_bpf_text(stack_bytes=DWARF_STACK_BYTES,
                                reg_count=DWARF_REG_COUNT,
                                force_bpf_task_pt_regs=None):
    return _DwarfProfileSnippetProvider.get_sample_bpf_text(
        stack_bytes=stack_bytes,
        reg_count=reg_count,
        force_bpf_task_pt_regs=force_bpf_task_pt_regs)


def has_bpf_task_pt_regs():
    return _DwarfProfileSnippetProvider.probe_task_pt_regs_support()


def bpf_task_pt_regs_probe_error():
    return _DwarfProfileSnippetProvider.bpf_task_pt_regs_error



def dwarf_event_to_regs(event, arch=GU_ARCH_X86_64):
    expected_mask = (1 << DWARF_REG_COUNT) - 1
    if getattr(event, "valid_mask", 0) != expected_mask:
        raise ValueError("DWARF event has invalid register mask")
    regs = GuRegs(arch=arch)
    for regno in range(DWARF_REG_COUNT):
        regs.set(regno, event.regs[regno])
    return regs


def decode_dwarf_sample(unwinder, pid, sample, unique_id=0, max_frames=0,
                        arch=GU_ARCH_X86_64):
    regs = dwarf_event_to_regs(sample, arch=arch)
    stack_data = bytes(bytearray(sample.stack[:sample.stack_size]))
    return unwinder.sample(pid, regs, stack_data=stack_data,
                           unique_id=unique_id, max_frames=max_frames)


def dwarf_frame_name(frame):
    addr = frame.abs_pc if frame.abs_pc else frame.pc
    if frame.symbol:
        return frame.symbol
    if frame.elf and frame.elf.base_name:
        return "%s+0x%x" % (frame.elf.base_name, frame.offset)
    return "0x%x" % addr


def format_dwarf_frame(frame, include_address=False):
    name = dwarf_frame_name(frame)
    addr = frame.abs_pc if frame.abs_pc else frame.pc
    if include_address:
        return "0x%016x %s" % (addr, name)
    return name


def dwarf_synthetic_stack_table():
    return (DWARF_MISSED_STACK,)
