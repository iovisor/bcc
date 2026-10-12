#!/usr/bin/env python3
# Copyright (c) 2026 Bytedance, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes as ct
import errno
from unittest import TestCase, main, skipUnless, mock

from bcc.dwarf import (
    BCC_DWARF_UNWIND_REASON_PROCESS_EXIT,
    DWARF_MISSED_STACK,
    _DwarfProfileSnippetProvider,
    bpf_task_pt_regs_probe_error,
    build_dwarf_profile_bpf_text,
    build_dwarf_sample_bpf_text,
    decode_dwarf_sample,
    dwarf_event_to_regs,
    dwarf_synthetic_stack_table,
    format_dwarf_frame,
    GU_ARCH_NATIVE,
    GU_REGS_MAX_DWARF_REGS,
    GU_REGS_VERSION,
    has_bpf_task_pt_regs,
    DwarfUnwindError,
    DwarfUnwinder,
    GuRegs,
    DwarfUnwindFrame,
)
from bcc.libbcc import (
    bcc_dwarf_unwind_elf,
    bcc_dwarf_unwind_frame,
    bcc_dwarf_unwind_options,
    bcc_dwarf_unwind_result,
    bcc_dwarf_unwind_sample,
    lib,
)


class TestDwarfUnwind(TestCase):
    def test_ctypes_layout_is_sized_for_c_abi(self):
        options = bcc_dwarf_unwind_options()
        sample = bcc_dwarf_unwind_sample()
        frame = bcc_dwarf_unwind_frame()
        elf = bcc_dwarf_unwind_elf()
        result = bcc_dwarf_unwind_result()

        self.assertEqual(options.size, ct.sizeof(options))
        self.assertEqual(sample.size, ct.sizeof(sample))
        self.assertEqual(frame.size, ct.sizeof(frame))
        self.assertEqual(elf.size, ct.sizeof(elf))
        self.assertEqual(result.size, ct.sizeof(result))
        self.assertEqual(GU_REGS_VERSION, 1)
        self.assertEqual(GU_REGS_MAX_DWARF_REGS, 64)

    def test_context_lifecycle_is_idempotent(self):
        self.assertEqual(DwarfUnwinder.supported(),
                         lib.bcc_dwarf_unwind_supported())

        unwinder = DwarfUnwinder()
        unwinder.close()
        unwinder.close()

        with DwarfUnwinder() as scoped:
            self.assertIsNotNone(scoped)

    def test_sample_reports_unsupported_or_invalid_input(self):
        regs = GuRegs()
        regs.set(0, 0x1234)

        with DwarfUnwinder() as unwinder:
            if not DwarfUnwinder.supported():
                with self.assertRaises(DwarfUnwindError) as cm:
                    unwinder.sample(pid=1, regs=regs, stack_data=b"\0" * 64)
                self.assertEqual(cm.exception.errno, errno.ENOTSUP)
                return

            with self.assertRaises(DwarfUnwindError) as cm:
                unwinder.sample(pid=0, regs=regs, stack_data=b"\0" * 64)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

    @skipUnless(lib.bcc_dwarf_unwind_supported(),
                "requires enabled DWARF unwinder")
    def test_enabled_sample_returns_owned_python_result(self):
        regs = GuRegs()

        with DwarfUnwinder() as unwinder:
            result = unwinder.sample(pid=99999999, regs=regs,
                                     stack_data=b"\0" * 64,
                                     max_frames=8)

        self.assertLess(result.unwind_ret, 0)
        self.assertEqual(result.stop_reason,
                         BCC_DWARF_UNWIND_REASON_PROCESS_EXIT)
        self.assertEqual(result.frames, [])

    def test_gu_regs_exposes_register_mask(self):
        regs = GuRegs(arch=GU_ARCH_NATIVE)

        self.assertTrue(regs.set(16, 0xfeedface))
        self.assertEqual(regs.get(16), 0xfeedface)
        self.assertIsNone(regs.get(17))
        self.assertFalse(regs.set(GU_REGS_MAX_DWARF_REGS, 1))

    def test_build_dwarf_profile_bpf_text_uses_helper_when_available(self):
        text = build_dwarf_profile_bpf_text(force_bpf_task_pt_regs=True)

        self.assertIn("(struct bcc_dwarf_sample *)&event->stack_size", text)
        self.assertIn("struct bcc_dwarf_sample", text)
        self.assertIn("bcc_dwarf_fill_sample_from_regs", text)
        self.assertIn("bpf_get_current_task_btf()", text)
        self.assertIn("bpf_task_pt_regs(task)", text)
        self.assertNotIn("bcc_dwarf_raw_task_regs_fallback", text)
        self.assertNotIn("BCC_DWARF_RAW_TASK_REGS_FALLBACK", text)

    def test_build_dwarf_profile_bpf_text_requires_helper(self):
        with self.assertRaises(RuntimeError):
            build_dwarf_profile_bpf_text(force_bpf_task_pt_regs=False)

        previous_state = _DwarfProfileSnippetProvider.has_bpf_task_pt_regs
        _DwarfProfileSnippetProvider.has_bpf_task_pt_regs = False
        try:
            with self.assertRaises(RuntimeError):
                build_dwarf_profile_bpf_text()
        finally:
            _DwarfProfileSnippetProvider.has_bpf_task_pt_regs = previous_state

    def test_dwarf_event_to_regs_formats_frames(self):
        regs = (ct.c_uint64 * 17)()
        for idx in range(17):
            regs[idx] = idx + 1
        event = type("Event", (), {
            "regs": regs,
            "valid_mask": (1 << 17) - 1,
        })()

        converted = dwarf_event_to_regs(event, arch=GU_ARCH_NATIVE)
        self.assertEqual(converted.get(0), 1)
        self.assertEqual(converted.get(16), 17)

    def test_dwarf_event_to_regs_rejects_invalid_mask(self):
        regs = (ct.c_uint64 * 17)()
        event = type("Event", (), {"regs": regs, "valid_mask": 0})()

        with self.assertRaises(ValueError):
            dwarf_event_to_regs(event, arch=GU_ARCH_NATIVE)

    def test_profile_bpf_drops_invalid_dwarf_samples(self):
        text = build_dwarf_profile_bpf_text(force_bpf_task_pt_regs=True)

        self.assertIn("if (!bcc_dwarf_fill_sample(ctx,", text)
        self.assertIn("return 0;\n\n    dwarf_events.perf_submit", text)

    def test_profile_bpf_captures_stack_from_page_aligned_sp(self):
        text = build_dwarf_profile_bpf_text(force_bpf_task_pt_regs=True)

        self.assertIn("user_stack_base = user_sp & ~(PAGE_SIZE - 1)", text)
        self.assertIn("(void *)user_stack_base", text)
        self.assertIn("sample->stack_size = PAGE_SIZE", text)
        self.assertIn("sample->stack_size += PAGE_SIZE", text)
        self.assertNotIn("(void *)user_sp) < 0", text)

    def test_sample_bpf_text_provides_hook_helper(self):
        text = build_dwarf_sample_bpf_text(force_bpf_task_pt_regs=True)

        self.assertIn("struct bcc_dwarf_sample", text)
        self.assertIn("bcc_dwarf_fill_sample_from_regs", text)
        self.assertIn("bpf_task_pt_regs(task)", text)
        self.assertNotIn("BPF_PERF_OUTPUT(dwarf_events)", text)
        self.assertNotIn("struct dwarf_event_t", text)

    def test_format_dwarf_frame(self):
        frame = DwarfUnwindFrame(pc=0x123, abs_pc=0, offset=0x20,
                                 symbol="demo", elf=None)
        self.assertEqual(format_dwarf_frame(frame), "demo")
        self.assertEqual(format_dwarf_frame(frame, include_address=True),
                         "0x0000000000000123 demo")

    def test_synthetic_stack_table(self):
        self.assertEqual(dwarf_synthetic_stack_table(), (DWARF_MISSED_STACK,))

    def test_decode_dwarf_sample_uses_event_sample_payload(self):
        calls = []

        class FakeUnwinder(object):
            def sample(self, *args, **kwargs):
                calls.append((args, kwargs))
                return "ok"

        regs = (ct.c_uint64 * 17)()
        stack = (ct.c_uint8 * 8)(*range(8))
        event_sample = type("Sample", (), {
            "regs": regs,
            "valid_mask": (1 << 17) - 1,
            "stack": stack,
            "stack_size": 4,
        })()

        self.assertEqual(decode_dwarf_sample(FakeUnwinder(), 1234, event_sample,
                                             unique_id=99, max_frames=7),
                         "ok")

        args, kwargs = calls[0]
        self.assertEqual(args[0], 1234)
        self.assertEqual(kwargs["stack_data"], b"\x00\x01\x02\x03")
        self.assertEqual(kwargs["unique_id"], 99)
        self.assertEqual(kwargs["max_frames"], 7)

    @mock.patch("bcc.BPF")
    def test_has_bpf_task_pt_regs_probe_is_cached(self, BPF):
        BPF.PERF_EVENT = 4
        BPF.return_value.load_func.return_value = object()
        _DwarfProfileSnippetProvider.has_bpf_task_pt_regs = None
        _DwarfProfileSnippetProvider.bpf_task_pt_regs_error = "old error"

        self.assertTrue(has_bpf_task_pt_regs())
        self.assertTrue(has_bpf_task_pt_regs())
        self.assertIsNone(bpf_task_pt_regs_probe_error())

        # Cached result avoids re-running the probe.
        self.assertEqual(BPF.call_count, 1)
        BPF.return_value.load_func.assert_called_once()

    @mock.patch("bcc.BPF")
    def test_has_bpf_task_pt_regs_probe_handles_unavailable(self, BPF):
        BPF.side_effect = RuntimeError("unsupported")
        _DwarfProfileSnippetProvider.has_bpf_task_pt_regs = None
        _DwarfProfileSnippetProvider.bpf_task_pt_regs_error = None

        self.assertFalse(has_bpf_task_pt_regs())
        self.assertEqual(bpf_task_pt_regs_probe_error(), "unsupported")


if __name__ == "__main__":
    main()
