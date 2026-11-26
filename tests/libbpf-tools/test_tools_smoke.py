#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License")
#
# Smoke tests for libbpf-tools: verify that each tested tool loads, attaches
# and exits cleanly either after its own duration or after receiving SIGINT.
#
# Set LIBBPF_TOOLS_DIR to test binaries built or installed elsewhere.
# Set LIBBPF_TOOLS_TEST_LOGFILE to also append the unittest report to a file.

import contextlib
import os
import signal
import subprocess
from unittest import main, skipUnless, TestCase

from utils import LoggingTestRunner

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.abspath(os.environ.get(
    "LIBBPF_TOOLS_DIR", os.path.join(TESTS_DIR, "..", "..", "libbpf-tools")))

FILESYSTEMS = ["btrfs", "ext4", "fuse", "nfs", "xfs", "f2fs", "bcachefs",
               "zfs"]


def fs_available(fs):
    try:
        with open("/proc/filesystems", "r") as f:
            names = [line.split()[-1] for line in f if line.strip()]
    except OSError:
        return False
    return fs in names or (fs == "nfs" and "nfs4" in names)


def kfunc_exists(*funcs):
    """True if any of the given kernel functions is in /proc/kallsyms."""
    wanted = set(funcs)
    with open("/proc/kallsyms", "r") as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 3 and fields[2] in wanted:
                return True
    return False


def has_hw_pmu():
    try:
        names = os.listdir("/sys/bus/event_source/devices")
    except OSError:
        return False
    return any(n in ("cpu", "cpu_core", "cpu_atom") or n.startswith("armv")
               for n in names)


def has_cpufreq():
    return os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq")


def _fail_msg(cmd, rc, stderr, reason):
    return "%s\n\tcommand: %s\n\texit code: %s\n\tstderr:\n%s" % (
        reason, " ".join(cmd), rc, stderr.strip())


class ToolTestCase(TestCase):
    def tool(self, name):
        path = os.path.join(TOOLS_DIR, name)
        self.assertTrue(os.access(path, os.X_OK),
                        "%s is missing or not executable" % path)
        return path

    @staticmethod
    def _communicate(proc, timeout):
        _, err = proc.communicate(timeout=timeout)
        return err.decode("utf-8", "replace")

    @staticmethod
    def _kill_process_group(proc):
        # A child of the tool can keep stderr open after the tool exits.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    # The tool runs in its own session so that its whole process group can be
    # killed on timeout. That also detaches it from the terminal's Ctrl-C, so
    # kill it here if the test is interrupted before the tool is reaped.
    @contextlib.contextmanager
    def _spawn(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            yield proc
        finally:
            if proc.returncode is None:
                self._kill_process_group(proc)
                self._communicate(proc, None)

    # Use this for commands that stop on their own (interval/count or
    # duration arguments). They are only killed in case of a hard hang.
    def run_with_duration(self, name, *args, timeout=30):
        cmd = [self.tool(name)] + list(args)
        with self._spawn(cmd) as proc:
            try:
                err = self._communicate(proc, timeout)
            except subprocess.TimeoutExpired:
                self._kill_process_group(proc)
                err = self._communicate(proc, None)
                self.fail(_fail_msg(cmd, proc.returncode, err,
                                    "did not exit within %ds" % timeout))
        self.assertEqual(0, proc.returncode, _fail_msg(
            cmd, proc.returncode, err, "did not exit cleanly"))

    # Use this for commands that run until interrupted. SIGINT is sent after
    # `timeout` seconds and the tool must exit with code 0 within
    # `kill_timeout` seconds; exiting early or hanging is a failure.
    def run_with_int(self, name, *args, timeout=5, kill_timeout=10):
        cmd = [self.tool(name)] + list(args)
        with self._spawn(cmd) as proc:
            try:
                err = self._communicate(proc, timeout)
            except subprocess.TimeoutExpired:
                pass
            else:
                self.fail(_fail_msg(cmd, proc.returncode, err,
                                    "exited before SIGINT was sent"))
            proc.send_signal(signal.SIGINT)
            try:
                err = self._communicate(proc, kill_timeout)
            except subprocess.TimeoutExpired:
                self._kill_process_group(proc)
                err = self._communicate(proc, None)
                self.fail(_fail_msg(cmd, proc.returncode, err,
                                    "did not exit within %ds after SIGINT" %
                                    kill_timeout))
        self.assertEqual(0, proc.returncode, _fail_msg(
            cmd, proc.returncode, err, "did not exit cleanly on SIGINT"))


@skipUnless(os.geteuid() == 0, "requires root")
@skipUnless(os.path.exists("/sys/kernel/btf/vmlinux"),
            "requires kernel BTF (/sys/kernel/btf/vmlinux)")
class SmokeTests(ToolTestCase):
    """Load, attach and run the explicitly listed tools for a short time."""

    def any_fs(self):
        for fs in FILESYSTEMS:
            if fs_available(fs):
                return fs
        self.skipTest("no supported filesystem available")

    def fsdist(self, fs):
        if not fs_available(fs):
            self.skipTest("%s is not available" % fs)
        self.run_with_duration(fs + "dist", "1", "1")

    def fsslower(self, fs):
        if not fs_available(fs):
            self.skipTest("%s is not available" % fs)
        self.run_with_duration(fs + "slower", "-d", "1")

    def test_bashreadline(self):
        self.run_with_int("bashreadline")

    def test_bindsnoop(self):
        self.run_with_int("bindsnoop")

    def test_biolatency(self):
        self.run_with_duration("biolatency", "1", "1")

    def test_biopattern(self):
        self.run_with_duration("biopattern", "1", "1")

    def test_biosnoop(self):
        self.run_with_int("biosnoop")

    def test_biostacks(self):
        self.run_with_duration("biostacks", "1")

    def test_biotop(self):
        self.run_with_duration("biotop", "-C", "1", "1")

    def test_bitesize(self):
        self.run_with_duration("bitesize", "1", "1")

    def test_cachestat(self):
        self.run_with_duration("cachestat", "1", "1")

    def test_capable(self):
        self.run_with_int("capable")

    def test_cpudist(self):
        self.run_with_duration("cpudist", "1", "1")

    @skipUnless(has_cpufreq(), "requires CPU frequency scaling")
    def test_cpufreq(self):
        self.run_with_duration("cpufreq", "-d", "1")

    def test_drsnoop(self):
        self.run_with_duration("drsnoop", "-d", "1")

    def test_execsnoop(self):
        self.run_with_int("execsnoop")

    def test_exitsnoop(self):
        self.run_with_int("exitsnoop")

    def test_filelife(self):
        self.run_with_int("filelife")

    def test_filetop(self):
        self.run_with_duration("filetop", "-C", "1", "1")

    def test_fsdist(self):
        self.run_with_duration("fsdist", "-t", self.any_fs(), "1", "1")

    def test_fsslower(self):
        self.run_with_duration("fsslower", "-t", self.any_fs(), "-d", "1")

    def test_btrfsdist(self):
        self.fsdist("btrfs")

    def test_btrfsslower(self):
        self.fsslower("btrfs")

    def test_ext4dist(self):
        self.fsdist("ext4")

    def test_ext4slower(self):
        self.fsslower("ext4")

    def test_fusedist(self):
        self.fsdist("fuse")

    def test_fuseslower(self):
        self.fsslower("fuse")

    def test_nfsdist(self):
        self.fsdist("nfs")

    def test_nfsslower(self):
        self.fsslower("nfs")

    def test_xfsdist(self):
        self.fsdist("xfs")

    def test_xfsslower(self):
        self.fsslower("xfs")

    def test_f2fsdist(self):
        self.fsdist("f2fs")

    def test_f2fsslower(self):
        self.fsslower("f2fs")

    def test_bcachefsdist(self):
        self.fsdist("bcachefs")

    def test_bcachefsslower(self):
        self.fsslower("bcachefs")

    def test_zfsdist(self):
        self.fsdist("zfs")

    def test_zfsslower(self):
        self.fsslower("zfs")

    def test_funclatency(self):
        self.run_with_duration("funclatency", "-d", "1", "vfs_read")

    def test_futexctn(self):
        self.run_with_duration("futexctn", "1", "1")

    def test_gethostlatency(self):
        self.run_with_int("gethostlatency")

    def test_hardirqs(self):
        self.run_with_duration("hardirqs", "1", "1")

    def test_javagc(self):
        self.skipTest("requires a running JVM")

    def test_klockstat(self):
        self.run_with_duration("klockstat", "-d", "1")

    def test_ksnoop(self):
        self.run_with_int("ksnoop", "trace", "vfs_read")

    @skipUnless(has_hw_pmu(), "requires hardware PMU")
    def test_llcstat(self):
        self.run_with_duration("llcstat", "1")

    def test_mdflush(self):
        if not kfunc_exists("md_flush_request"):
            self.skipTest("md_flush_request is not available")
        self.run_with_int("mdflush")

    def test_memleak(self):
        self.run_with_duration("memleak", "1", "1")

    def test_mountsnoop(self):
        self.run_with_int("mountsnoop")

    def test_numamove(self):
        if not kfunc_exists("migrate_misplaced_page",
                            "migrate_misplaced_folio"):
            self.skipTest("migrate_misplaced_{page,folio} not available")
        self.run_with_int("numamove")

    def test_offcputime(self):
        self.run_with_duration("offcputime", "1")

    def test_oomkill(self):
        self.run_with_int("oomkill")

    def test_opensnoop(self):
        self.run_with_duration("opensnoop", "-d", "1")

    def test_profile(self):
        self.run_with_duration("profile", "1")

    def test_readahead(self):
        self.run_with_duration("readahead", "-d", "1")

    def test_runqlat(self):
        self.run_with_duration("runqlat", "1", "1")

    def test_runqlen(self):
        self.run_with_duration("runqlen", "1", "1")

    def test_runqslower(self):
        self.run_with_int("runqslower")

    def test_sigsnoop(self):
        self.run_with_int("sigsnoop")

    def test_killsnoop(self):
        self.run_with_int("killsnoop")

    def test_slabratetop(self):
        self.run_with_duration("slabratetop", "-C", "1", "1")

    def test_softirqs(self):
        self.run_with_duration("softirqs", "1", "1")

    def test_softirqslower(self):
        self.run_with_int("softirqslower")

    def test_solisten(self):
        self.run_with_int("solisten")

    def test_statsnoop(self):
        self.run_with_int("statsnoop")

    def test_syncsnoop(self):
        self.run_with_int("syncsnoop")

    def test_syscount(self):
        self.run_with_duration("syscount", "-d", "1")

    def test_tcpconnect(self):
        self.run_with_int("tcpconnect")

    def test_tcpconnlat(self):
        self.run_with_int("tcpconnlat")

    def test_tcplife(self):
        self.run_with_int("tcplife")

    def test_tcppktlat(self):
        self.run_with_int("tcppktlat")

    def test_tcprtt(self):
        self.run_with_duration("tcprtt", "-d", "1")

    def test_tcpstates(self):
        self.run_with_int("tcpstates")

    def test_tcpsynbl(self):
        self.run_with_duration("tcpsynbl", "1", "1")

    def test_tcptop(self):
        self.run_with_duration("tcptop", "-C", "1", "1")

    def test_tcptracer(self):
        self.run_with_int("tcptracer")

    def test_vfsstat(self):
        self.run_with_duration("vfsstat", "1", "1")

    def test_wakeuptime(self):
        self.run_with_duration("wakeuptime", "1")


if __name__ == "__main__":
    main(testRunner=LoggingTestRunner)
