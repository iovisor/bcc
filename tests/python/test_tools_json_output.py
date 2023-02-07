#!/usr/bin/env python3
# Copyright (c) Sasha Goldshtein, 2017
# Licensed under the Apache License, Version 2.0 (the "License")

import distutils.version
import subprocess
import os
import re
from unittest import main, skipUnless, TestCase
from utils import mayFail, kernel_version_ge
import ast
import json

TOOLS_DIR = "./tools/"

def _helpful_rc_msg(rc, allow_early, kill):
    s = "rc was %d\n" % rc
    if rc == 0:
        s += "\tMeaning: command returned successfully before test timeout\n"
    elif rc == 124:
        s += "\tMeaning: command was killed by INT signal\n"
    elif rc == 137:
        s += "\tMeaning: command was killed by KILL signal\n"

    s += "Command was expected to do one of:\n"
    s += "\tBe killed by SIGINT\n"
    if kill:
        s += "\tBe killed by SIGKILL\n"
    if allow_early:
        s += "\tSuccessfully return before being killed\n"

    return s

@skipUnless(kernel_version_ge(4,1), "requires kernel >= 4.1")
class SmokeTests(TestCase):
    # Use this for commands that have a built-in timeout, so they only need
    # to be killed in case of a hard hang.
    def run_with_duration(self, command, output={}, timeout=10):
        full_command = TOOLS_DIR + command
        with subprocess.Popen(full_command, shell=True, stdout=subprocess.PIPE) as p:
            while True:
                line = p.stdout.readline()
                if not line:
                    break
                self.assertEqual(json.loads(line.decode().replace("\'", "\"")).keys(),
                                    output.keys(), ("Failed to get the expected json output for %s" % command))

    # Use this for commands that don't have a built-in timeout, so we have
    # to Ctrl-C out of them by sending SIGINT. If that still doesn't stop
    # them, send a kill signal 5 seconds later.
    def run_with_int(self, command, timeout=5, kill_timeout=5,
                     allow_early=False, kill=False):
        full_command = TOOLS_DIR + command
        signal = "KILL" if kill else "INT"
        rc = subprocess.call("timeout -s %s -k %ds %ds %s > /dev/null" %
                (signal, kill_timeout, timeout, full_command), shell=True)
        # timeout returns 124 if the program did not terminate prematurely,
        # and returns 137 if we used KILL instead of INT. So there are three
        # sensible scenarios:
        #   1. The script is allowed to return early, and it did, with a
        #      success return code.
        #   2. The script timed out and was killed by the SIGINT signal.
        #   3. The script timed out and was killed by the SIGKILL signal, and
        #      this was what we asked for using kill=True.
        self.assertTrue((rc == 0 and allow_early) or rc == 124
                        or (rc == 137 and kill), _helpful_rc_msg(rc,
                        allow_early, kill))

    def kmod_loaded(self, mod):
        with open("/proc/modules", "r") as mods:
            reg = re.compile("^%s\s" % mod)
            for line in mods:
                if reg.match(line):
                    return 1
                return 0

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_argdist(self):
        sample = {'time': '14:20:49', 'syscall': 'read', 'count': 2245}
        self.run_with_duration("syscount.py -j -i 1 -d 1", sample)

    # TODO: enable run_with_int test 
    # @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    # def test_bashreadline(self):
    #     self.run_with_int("bashreadline.py")

    # TODO: enable run_with_int test
    # @skipUnless(kernel_version_ge(4,4), "requires kernel >= 4.4")
    # def test_bindsnoop(self):
    #     self.run_with_int("bindsnoop.py")
    
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_biolatency(self):
        sample = {'ts': '2023-02-06 14:02:39', 'val_type': 'usecs', 'data': [{'interval-start': 0, 'interval-end': 1, 'count': 0}, {'interval-start': 2, 'interval-end': 3, 'count': 0}, {'interval-start': 4, 'interval-end': 7, 'count': 0}, {'interval-start': 8, 'interval-end': 15, 'count': 0}, {'interval-start': 16, 'interval-end': 31, 'count': 0}, {'interval-start': 32, 'interval-end': 63, 'count': 1}, {'interval-start': 64, 'interval-end': 127, 'count': 2}, {'interval-start': 128, 'interval-end': 255, 'count': 3}, {'interval-start': 256, 'interval-end': 511, 'count': 4}]}
        self.run_with_duration("biolatency.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_biopattern(self):
    #     sample = {"time": "15:17:50", "disk": "sda", "random": 100, "sequential": 0, "count": 22, "kbytes": 96.0}
    #     self.run_with_int("biopattern.py -j 1 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_biotop(self):
        sample = {"pid": 325, "comm": "systemd-journal", "operation": "read", "major": 8, "minor": 0, "io": 3, "kbytes": 124.0, "avg_ms": 0.598, "disk": "sda"}
        self.run_with_duration("biotop.py -j 1 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_bitesize(self):
        sample = {'ts': '2023-02-06 15:51:04', 'val_type': 'kbytes', 'data': [{'interval-start': 0, 'interval-end': 1, 'count': 1}], 'comm': 'kworker/u16:0'}
        self.run_with_duration("bitesize.py -j -d 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_cachestat(self):
        sample = {"hits": 18359, "misses": 24, "dirties": 55, "hitratio": 0.9986944459555024, "buffers_mb": 147.3828125, "cached_mb": 1511.16796875}
        self.run_with_duration("cachestat.py -j 1 1", sample)
    
    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_cachetop(self):
        sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
        self.run_with_duration("cachetop.py -j 1 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_cpudist(self):
        sample = {'ts': '2023-02-07 09:35:15', 'val_type': 'usecs', 'data': [{'interval-start': 0, 'interval-end': 1, 'count': 0}, {'interval-start': 2, 'interval-end': 3, 'count': 11}, {'interval-start': 4, 'interval-end': 7, 'count': 50}, {'interval-start': 8, 'interval-end': 15, 'count': 123}, {'interval-start': 16, 'interval-end': 31, 'count': 160}, {'interval-start': 32, 'interval-end': 63, 'count': 207}, {'interval-start': 64, 'interval-end': 127, 'count': 356}, {'interval-start': 128, 'interval-end': 255, 'count': 406}, {'interval-start': 256, 'interval-end': 511, 'count': 115}, {'interval-start': 512, 'interval-end': 1023, 'count': 24}, {'interval-start': 1024, 'interval-end': 2047, 'count': 7}, {'interval-start': 2048, 'interval-end': 4095, 'count': 8}, {'interval-start': 4096, 'interval-end': 8191, 'count': 3}, {'interval-start': 8192, 'interval-end': 16383, 'count': 1}, {'interval-start': 16384, 'interval-end': 32767, 'count': 4}, {'interval-start': 32768, 'interval-end': 65535, 'count': 1}, {'interval-start': 65536, 'interval-end': 131071, 'count': 1}]}
        self.run_with_duration("cpudist.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_dcsnoop(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("dcsnoop.py -j", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_dcstat(self):
        sample = {'REFS': 7221.0, 'SLOW': 79.0, 'MISS': 48.0, 'HIT%': 99.33527212297466}
        self.run_with_duration("dcstat.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_drsnoop(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("drsnoop.py -j", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_execsnoop(self):
    #     sample = {"comm": "sleep", "pid": 477788, "ppid": 477782, "retval": 0, "args": ["/usr/bin/sleep", "1"], "uid": 1000, "timestamp": 3.693091630935669}
    #     self.run_with_duration("execsnoop.py -j", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_exitsnoop(self):
    #     sample = {"timestamp": "2023-02-07T09:53:31.492", "task": "cat", "pid": 478082, "ppid": 478077, "tid": 478082, "age": 0.000976737, "exit_code": 0, "sig_info": 0}
    #     self.run_with_duration("exitsnoop.py -j", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_ext4dist(self):
        sample = {'ts': '2023-02-07 10:01:02', 'val_type': 'usecs', 'data': [{'interval-start': 0, 'interval-end': 1, 'count': 52}, {'interval-start': 2, 'interval-end': 3, 'count': 1}], 'operation': 'read'}
        self.run_with_duration("ext4dist.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_ext4slower(self):
    #     sample = {"time": "10:11:32", "task": "ib_log_flush", "pid": 1155, "type": 3, "size": 0, "offset": 0, "delta": 1.07, "filename": "ib_logfile0"}
    #     self.run_with_duration("ext4slower.py --json 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_filetop(self):
        sample = {'pid': 480769, 'comm': 'sed', 'reads': 2, 'writes': 0, 'rbytes': 2.0, 'wbytes': 0.0, 'type': 'R', 'file': 'filesystems'}
        self.run_with_duration("filetop.py -j 1 1", sample)

    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_funccount(self):
        # Changes output depending on the function being traces
        # TODO: test for valid json

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_hardirqs(self):
        sample = {'hardirq': 'iwlwifi', 'total_usecs': 117.603}
        self.run_with_duration("hardirqs.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_killsnoop(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("killsnoop.py -j", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_llcstat(self):
        sample = {"pid": 6750, "name": "uwsgi", "cpu": 4, "ref": 7100, "miss": 5900, "hit": 16.90}
        self.run_with_duration("llcstat.py -j 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_netqtop(self):
        sample = {"time": "Tue Feb  7 10:46:48 2023", "direction": "rx", "queue": 0, "avg_size": 0, "size_64B": 0, "size_512B": 0, "size_2K": 0, "size_16K": 0, "size_64K": 0, "BPS": 0, "PPS": 0}
        self.run_with_duration("netqtop.py -j -i 1 -d 1 -n lo", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_opensnoop(self):
        sample = {'PID': 339993, 'COMM': 'code', 'FD': 51, 'ERR': 0, 'PATH': '/proc/487112/cmdline'}
        self.run_with_duration("opensnoop.py -j -d 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_runqlen(self):
        sample = {'ts': '2023-02-07 11:07:35', 'val_type': 'runqlen', 'data': []}
        self.run_with_duration("runqlen.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_runqslower(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("runqslower.py -j", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_slabratetop(self):
        sample = {"time": "11:14:08", "cache": "names_cache", "allocs": 2775, "bytes": 11366400}
        self.run_with_duration("slabratetop.py -j 1 1", sample)

    # TODO: implement test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_sofdsnoop(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("sofdsnoop.py -j -d 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_softirqs(self):
        sample = {'time': '11:20:50', 'softirq': 'sched', 'total_usecs': 12808.425}
        self.run_with_duration("softirqs.py -j 1 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_syscount(self):
        sample = {'time': '11:22:44', 'syscall': 'select', 'count': 488}
        self.run_with_duration("syscount.py -j -i 1 -d 1", sample)

    # TODO: implement test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcpaccept(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("tcpaccept.py -j 1 1", sample)

    # TODO: implement test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcpcong(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("tcpcong.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcpconnect(self):
    #     sample = {"ts": 0, "uid": 0, "pid": 334844, "task": "Socket Thread", "ip": 4, "saddr": "192.168.18.11", "daddr": "152.199.19.160", "dport": 443, "query": ""}
    #     self.run_with_duration("tcpconnect.py -j", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_tcpconnlat(self):
        sample = {"timestamp": 12.572059, "pid": 1162, "task": "python3", "ip": 4, "saddr": "192.168.18.11", "daddr": "192.168.18.11", "lport": 33944, "dport": 5000, "lat (ms)": 0.039}
        self.run_with_duration("tcpconnlat.py -j -d 1", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_tcplife(self):
        sample = {"time": "11:33:29", "timestamp": 2.660002, "pid": 334844, "task": "Socket Thread", "family": 4, "saddr": "192.168.18.11", "sport": 57506, "daddr": "172.217.170.66", "dport": 443, "tx_kb": 3.4052734375, "rx_kb": 6.3115234375, "ms": 2889.04}
        self.run_with_duration("tcplife.py -j -d 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcpretrans(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("tcpretrans.py -j", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcprtt(self):
    #     sample = {'ts': '2023-02-07 11:37:12', 'val_type': 'usecs', 'data': [{'interval-start': 0, 'interval-end': 1, 'count': 0}, {'interval-start': 2, 'interval-end': 3, 'count': 0}, {'interval-start': 4, 'interval-end': 7, 'count': 0}, {'interval-start': 8, 'interval-end': 15, 'count': 0}, {'interval-start': 16, 'interval-end': 31, 'count': 0}, {'interval-start': 32, 'interval-end': 63, 'count': 0}, {'interval-start': 64, 'interval-end': 127, 'count': 0}, {'interval-start': 128, 'interval-end': 255, 'count': 0}, {'interval-start': 256, 'interval-end': 511, 'count': 0}, {'interval-start': 512, 'interval-end': 1023, 'count': 0}, {'interval-start': 1024, 'interval-end': 2047, 'count': 0}, {'interval-start': 2048, 'interval-end': 4095, 'count': 0}, {'interval-start': 4096, 'interval-end': 8191, 'count': 0}, {'interval-start': 8192, 'interval-end': 16383, 'count': 0}, {'interval-start': 16384, 'interval-end': 32767, 'count': 2}], 'All Addresses': '*******'}
    #     self.run_with_duration("tcprtt.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcpstates(self):
    #     sample = {"time": "15:57:56", "pid": 6728, "uid": "0", "username": "root", "comm": "uwsgi", "hits": 1, "misses": 0, "dirties": 0, "read_hit_percent": 100.0, "write_hit_percent": 0}
    #     self.run_with_duration("tcpstates.py -j", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcpsynbl(self):
    #     sample = {'ts': '2023-02-07 11:40:02', 'val_type': 'backlog', 'data': [{'interval-start': 0, 'interval-end': 1, 'count': 1}], 'backlog_max': 128}
    #     self.run_with_duration("tcpsynbl.py -j", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_tcptracer(self):
    #     sample = {"timestamp": 0.0, "type": "connect", "pid": 334844, "comm": "Socket Thread", "ip": 4, "saddr": "192.168.18.11", "daddr": "172.217.170.4", "sport": 50250, "dport": 443, "netns": 4026531840}
    #     self.run_with_duration("tcptracer.py -j", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_threadsnoop(self):
    #     sample = {"time": 0.0, "pid": 287443, "comm": "xdg-desktop-por", "func": "[unknown]"}
    #     self.run_with_duration("threadsnoop.py -j 1 1", sample)

    # TODO: enable run_with_int test
    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_vfscount(self):
    #     sample = {"addr": 18446744071599422913, "func": "vfs_rename", "count": 6}
    #     self.run_with_duration("vfscount.py -j", sample)

    @mayFail("This fails on github actions environment, and needs to be fixed")
    def test_vfsstat(self):
        sample = {"READ": 3483.0, "WRITE": 446.0, "FSYNC": 0.0, "OPEN": 1522.0, "CREATE": 0.0}
        self.run_with_duration("vfsstat.py -j 1 1", sample)

if __name__ == "__main__":
    main()
