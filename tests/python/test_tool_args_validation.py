#!/usr/bin/env python3
# Copyright (c) 2026, BCC Contributors
# Licensed under the Apache License, Version 2.0 (the "License")

"""
Tests that BCC Python tools reject malicious non-integer input for
arguments that get interpolated into BPF C source code.

These tests do NOT require root — they only exercise argparse validation,
not BPF program loading.
"""

import os
import subprocess
import unittest

TOOLS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'tools')
OLD_TOOLS_DIR = os.path.join(TOOLS_DIR, 'old')

# Injection payloads that must be rejected
PAYLOADS = [
    '1234; } malicious(); if (0',
    '1 || 1',
    '$(whoami)',
    'abc',
    '1.5',
]


class TestToolArgsValidation(unittest.TestCase):
    """Test that tools reject non-integer values for numeric arguments."""

    def _assert_tool_rejects(self, tool_dir, tool, flag, payload):
        """Run a tool with a malicious payload and assert it fails."""
        tool_path = os.path.join(tool_dir, tool)
        if not os.path.exists(tool_path):
            self.skipTest("Tool not found: %s" % tool_path)

        result = subprocess.run(
            ['python3', tool_path, flag, payload],
            capture_output=True, text=True, timeout=10
        )
        self.assertNotEqual(result.returncode, 0,
            "Tool %s accepted malicious input %r for %s" % (tool, payload, flag))
        self.assertTrue(
            'error' in result.stderr.lower() or 'invalid' in result.stderr.lower(),
            "Tool %s stderr did not contain expected error for %s=%r:\n%s" % (
                tool, flag, payload, result.stderr))

    # --- Simple PID-only tools (tools/) ---

    def test_tcptop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'tcptop.py', '-p', p)

    def test_tcpconnlat_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'tcpconnlat.py', '-p', p)

    def test_tcplife_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'tcplife.py', '-p', p)

    def test_tcpaccept_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'tcpaccept.py', '-p', p)

    def test_capable_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'capable.py', '-p', p)

    def test_cpudist_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'cpudist.py', '-p', p)

    def test_statsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'statsnoop.py', '-p', p)

    def test_filelife_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'filelife.py', '-p', p)

    def test_filegone_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'filegone.py', '-p', p)

    def test_compactsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'compactsnoop.py', '-p', p)

    def test_vfsstat_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'vfsstat.py', '-p', p)

    def test_ext4dist_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'ext4dist.py', '-p', p)

    # --- PID + TID tools ---

    def test_shmsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'shmsnoop.py', '-p', p)

    def test_shmsnoop_tid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'shmsnoop.py', '-t', p)

    def test_sofdsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'sofdsnoop.py', '-p', p)

    def test_sofdsnoop_tid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'sofdsnoop.py', '-t', p)

    def test_numasched_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'numasched.py', '-p', p)

    def test_numasched_tid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'numasched.py', '-t', p)

    def test_klockstat_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'klockstat.py', '-p', p)

    def test_klockstat_tid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'klockstat.py', '-t', p)

    def test_opensnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'opensnoop.py', '-p', p)

    def test_opensnoop_tid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'opensnoop.py', '-t', p)

    def test_drsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'drsnoop.py', '-p', p)

    def test_drsnoop_tid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'drsnoop.py', '-t', p)

    # --- PID + UID tools ---

    def test_tcpconnect_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'tcpconnect.py', '-p', p)

    def test_tcpconnect_uid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'tcpconnect.py', '-u', p)

    def test_bindsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'bindsnoop.py', '-p', p)

    def test_bindsnoop_uid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'bindsnoop.py', '-u', p)

    # --- Filesystem slower tools ---

    def test_nfsslower_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'nfsslower.py', '-p', p)

    def test_xfsslower_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'xfsslower.py', '-p', p)

    def test_zfsslower_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'zfsslower.py', '-p', p)

    def test_ext4slower_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'ext4slower.py', '-p', p)

    def test_btrfsslower_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'btrfsslower.py', '-p', p)

    def test_f2fsslower_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'f2fsslower.py', '-p', p)

    # --- Special handling tools ---

    def test_execsnoop_max_args(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'execsnoop.py', '--max-args', p)

    def test_execsnoop_ppid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'execsnoop.py', '-P', p)

    def test_killsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'killsnoop.py', '-p', p)

    def test_killsnoop_tpid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'killsnoop.py', '-T', p)

    def test_killsnoop_signal(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'killsnoop.py', '-s', p)

    def test_ttysnoop_datasize(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'ttysnoop.py', '-s', p)

    def test_ttysnoop_datacount(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(TOOLS_DIR, 'ttysnoop.py', '-c', p)

    # --- Old tools ---

    def test_old_tcptop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'tcptop.py', '-p', p)

    def test_old_stacksnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'stacksnoop.py', '-p', p)

    def test_old_tcpconnect_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'tcpconnect.py', '-p', p)

    def test_old_statsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'statsnoop.py', '-p', p)

    def test_old_tcpaccept_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'tcpaccept.py', '-p', p)

    def test_old_filelife_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'filelife.py', '-p', p)

    def test_old_killsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'killsnoop.py', '-p', p)

    def test_old_opensnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'opensnoop.py', '-p', p)

    def test_old_stackcount_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'stackcount.py', '-p', p)

    def test_old_compactsnoop_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'compactsnoop.py', '-p', p)

    def test_old_filegone_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'filegone.py', '-p', p)

    def test_old_wakeuptime_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'wakeuptime.py', '-p', p)

    def test_old_offcputime_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'offcputime.py', '-p', p)

    def test_old_offwaketime_pid(self):
        for p in PAYLOADS:
            self._assert_tool_rejects(OLD_TOOLS_DIR, 'offwaketime.py', '-p', p)

    # --- Regression: valid integers should be accepted by argparse ---
    # (These will fail at BPF load without root, but argparse should not reject them)

    def test_valid_integer_accepted(self):
        """Verify argparse accepts valid integers (tool may fail later at BPF load)."""
        tool_path = os.path.join(TOOLS_DIR, 'tcptop.py')
        if not os.path.exists(tool_path):
            self.skipTest("Tool not found")
        result = subprocess.run(
            ['python3', tool_path, '-p', '1234'],
            capture_output=True, text=True, timeout=10
        )
        # Should NOT fail with argparse error (may fail with BPF error, that's ok)
        if result.returncode != 0:
            self.assertNotIn('invalid int value', result.stderr,
                "Valid integer '1234' was rejected by argparse")

    def test_killsnoop_valid_signal_list(self):
        """Verify killsnoop accepts valid comma-separated signal list."""
        tool_path = os.path.join(TOOLS_DIR, 'killsnoop.py')
        if not os.path.exists(tool_path):
            self.skipTest("Tool not found")
        result = subprocess.run(
            ['python3', tool_path, '-s', '9,15'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            self.assertNotIn('invalid positive_int_list value', result.stderr,
                "Valid signal list '9,15' was rejected by argparse")


if __name__ == "__main__":
    unittest.main()
