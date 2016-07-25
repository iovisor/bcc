# bcc Tutorial

This tutorial covers how to use [bcc](https://github.com/iovisor/bcc) tools to quickly solve performance, troubleshooting, and networking issues. If you want to develop new bcc tools, see [tutorial_bcc_python_developer.md](tutorial_bcc_python_developer.md) for that tutorial.

It is assumed for this tutorial that bcc is already installed, and you can run tools like execsnoop successfully. See [INSTALL.md](../INSTALL.md). This uses enhancements added to the Linux 4.x series.

## Observability

Some quick wins.

### 0. Before bcc

Before using bcc, you should start with the Linux basics. One reference is the [Linux Performance Analysis in 60s](http://techblog.netflix.com/2015/11/linux-performance-analysis-in-60s.html) post, which covers these commands:

1. uptime
1. dmesg | tail
1. vmstat 1
1. mpstat -P ALL 1
1. pidstat 1
1. iostat -xz 1
1. free -m
1. sar -n DEV 1
1. sar -n TCP,ETCP 1
1. top

### 1. General Performance

Here is a generic checklist for performance investigations with bcc, first as a list, then in detail:

1. execsnoop
1. opensnoop
1. ext4slower (or btrfs\*, xfs\*, zfs\*)
1. biolatency
1. biosnoop
1. cachestat
1. tcpconnect
1. tcpaccept
1. tcpretrans
1. runqlat
1. profile

These tools may be installed on your system under /usr/share/bcc/tools, or you can run them from the bcc github repo under /tools where they have a .py extension. Browse the 50+ tools available for more analysis options.

#### 1. execsnoop

```
# ./execsnoop
PCOMM            PID    RET ARGS
supervise        9660     0 ./run
supervise        9661     0 ./run
mkdir            9662     0 /bin/mkdir -p ./main
run              9663     0 ./run
[...]
```

execsnoop prints one line of output for each new process. Check for short-lived processes. These can consume CPU resources, but not show up in most monitoring tools that periodically take snapshots of which processes are running.

It works by tracing exec(), not the fork(), so it will catch many types of new processes but not all (eg, it won't see an application launching working processes, that doesn't exec() anything else).

More [examples](../tools/execsnoop_example.txt).

#### 2. opensnoop

```
# ./opensnoop
PID    COMM      FD ERR PATH
1565   redis-server        5   0 /proc/1565/stat
1565   redis-server        5   0 /proc/1565/stat
1565   redis-server        5   0 /proc/1565/stat
1603   snmpd               9   0 /proc/net/dev
1603   snmpd              11   0 /proc/net/if_inet6
1603   snmpd              -1   2 /sys/class/net/eth0/device/vendor
1603   snmpd              11   0 /proc/sys/net/ipv4/neigh/eth0/retrans_time_ms
1603   snmpd              11   0 /proc/sys/net/ipv6/neigh/eth0/retrans_time_ms
1603   snmpd              11   0 /proc/sys/net/ipv6/conf/eth0/forwarding
[...]
```

opensnoop prints one line of output for each open() syscall, including details.

Files that are opened can tell you a lot about how applications work: identifying their data files, config files, and log files. Sometimes applications can misbehave, and perform poorly, when they are constantly attempting to read files that do not exist. opensnoop gives you a quick look.

More [examples](../tools/opensnoop_example.txt).

#### 3. ext4slower (or btrfs\*, xfs\*, zfs\*)

```
# ./ext4slower
Tracing ext4 operations slower than 10 ms
TIME     COMM           PID    T BYTES   OFF_KB   LAT(ms) FILENAME
06:35:01 cron           16464  R 1249    0          16.05 common-auth
06:35:01 cron           16463  R 1249    0          16.04 common-auth
06:35:01 cron           16465  R 1249    0          16.03 common-auth
06:35:01 cron           16465  R 4096    0          10.62 login.defs
06:35:01 cron           16464  R 4096    0          10.61 login.defs
```

ext4slower traces the ext4 file system and times common operations, and then only prints those that exceed a threshold.

This is great for identifying or exonerating one type of performance issue: slow individually slow disk i/O via the file system. Disks process I/O asynchronously, and it can be difficult to associate latency at that layer with the latency applications experience. Tracing higher up in the kernel stack, at the VFS -> file system interface, will more closely match what an application suffers. Use this tool to identify if file system latency exceeds a given threshold.

Similar tools exist in bcc for other file systems: btrfsslower, xfsslower, and zfsslower. There is also fileslower, which works at the VFS layer and traces everything (although at some higher overhead).

More [examples](../tools/ext4slower_example.txt).

#### 4. biolatency

```
# ./biolatency
Tracing block device I/O... Hit Ctrl-C to end.
^C
     usecs           : count     distribution
       0 -> 1        : 0        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 0        |                                      |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 12       |********                              |
     256 -> 511      : 15       |**********                            |
     512 -> 1023     : 43       |*******************************       |
    1024 -> 2047     : 52       |**************************************|
    2048 -> 4095     : 47       |**********************************    |
    4096 -> 8191     : 52       |**************************************|
    8192 -> 16383    : 36       |**************************            |
   16384 -> 32767    : 15       |**********                            |
   32768 -> 65535    : 2        |*                                     |
   65536 -> 131071   : 2        |*                                     |
```

biolatency traces disk I/O latency (time from device issue to completion), and when the tool ends (Ctrl-C, or a given interval), it prints a histogram summary of the latency.

This is great for understanding disk I/O latency beyond the average times given by tools like iostat. I/O latency outliers will be visible at the end of the distribution, as well as multi-mode distributions.

More [examples](../tools/biolatency_example.txt).

#### 5. biosnoop

```
# ./biosnoop
TIME(s)        COMM           PID    DISK    T  SECTOR    BYTES   LAT(ms)
0.000004001    supervise      1950   xvda1   W  13092560  4096       0.74
0.000178002    supervise      1950   xvda1   W  13092432  4096       0.61
0.001469001    supervise      1956   xvda1   W  13092440  4096       1.24
0.001588002    supervise      1956   xvda1   W  13115128  4096       1.09
1.022346001    supervise      1950   xvda1   W  13115272  4096       0.98
1.022568002    supervise      1950   xvda1   W  13188496  4096       0.93
[...]
```

biosnoop prints a line of output for each disk I/O, with details including latency (time from device issue to completion).

This allows you to examine disk I/O in more detail, and look for time-ordered patterns (eg, reads queueing behind writes). Note that the output will be verbose if your system performance a high rate of disk I/O.

More [examples](../tools/biosnoop_example.txt).

#### 6. cachestat

```
# ./cachestat
    HITS   MISSES  DIRTIES  READ_HIT% WRITE_HIT%   BUFFERS_MB  CACHED_MB
    1074       44       13      94.9%       2.9%            1        223
    2195      170        8      92.5%       6.8%            1        143
     182       53       56      53.6%       1.3%            1        143
   62480    40960    20480      40.6%      19.8%            1        223
       7        2        5      22.2%      22.2%            1        223
     348        0        0     100.0%       0.0%            1        223
[...]
```

cachestat prints a one line summary every second (or every custom interval) showing statistics from the file system cache.

Use this to identify a low cache hit ratio, and a high rate of misses: which gives one lead for performance tuning.

More [examples](../tools/cachestat_example.txt).

#### 7. tcpconnect

```
# ./tcpconnect
PID    COMM         IP SADDR            DADDR            DPORT
1479   telnet       4  127.0.0.1        127.0.0.1        23
1469   curl         4  10.201.219.236   54.245.105.25    80
1469   curl         4  10.201.219.236   54.67.101.145    80
1991   telnet       6  ::1              ::1              23
2015   ssh          6  fe80::2000:bff:fe82:3ac fe80::2000:bff:fe82:3ac 22
[...]
```

tcpconnect prints one line of output for every active TCP connection (eg, via connect()), with details including source and destination addresses.

Look for unexpected connections that may point to inefficiencies in application configuration, or an intruder.

More [examples](../tools/tcpconnect_example.txt).

#### 8. tcpaccept

```
# ./tcpaccept
PID    COMM         IP RADDR            LADDR            LPORT
907    sshd         4  192.168.56.1     192.168.56.102   22
907    sshd         4  127.0.0.1        127.0.0.1        22
5389   perl         6  1234:ab12:2040:5020:2299:0:5:0 1234:ab12:2040:5020:2299:0:5:0 7001
[...]
```

tcpaccept prints one line of output for every passive TCP connection (eg, via accept()), with details including source and destination addresses.

Look for unexpected connections that may point to inefficiencies in application configuration, or an intruder.

More [examples](../tools/tcpaccept_example.txt).

#### 9. tcpretrans

```
# ./tcpretrans 
TIME     PID    IP LADDR:LPORT          T> RADDR:RPORT          STATE
01:55:05 0      4  10.153.223.157:22    R> 69.53.245.40:34619   ESTABLISHED
01:55:05 0      4  10.153.223.157:22    R> 69.53.245.40:34619   ESTABLISHED
01:55:17 0      4  10.153.223.157:22    R> 69.53.245.40:22957   ESTABLISHED
[...]
```

tcprerans prints one line of output for every TCP retransmit packet, with details including source and destination addresses, and kernel state of the TCP connection.

TCP retransmissions cause latency and throughput issues. For ESTABLESHID retransmits, look for patterns with networks. For SYN_SENT, this may point to target kernel CPU saturation and kernel packet drops.

More [examples](../tools/tcpretrans_example.txt).

#### 10. runqlat

```
# ./runqlat 
Tracing run queue latency... Hit Ctrl-C to end.
^C
     usecs               : count     distribution
         0 -> 1          : 233      |***********                             |
         2 -> 3          : 742      |************************************    |
         4 -> 7          : 203      |**********                              |
         8 -> 15         : 173      |********                                |
        16 -> 31         : 24       |*                                       |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 30       |*                                       |
       128 -> 255        : 6        |                                        |
       256 -> 511        : 3        |                                        |
       512 -> 1023       : 5        |                                        |
      1024 -> 2047       : 27       |*                                       |
      2048 -> 4095       : 30       |*                                       |
      4096 -> 8191       : 20       |                                        |
      8192 -> 16383      : 29       |*                                       |
     16384 -> 32767      : 809      |****************************************|
     32768 -> 65535      : 64       |***                                     |
```

runqlat times how long threads were waiting on the CPU run queues, and prints this as a histogram.

This can help quantify time lost waiting for a turn on CPU, during periods of CPU saturation.

More [examples](../tools/runqlat_example.txt).

#### 11. profile

```
# ./profile
Sampling at 49 Hertz of all threads by user + kernel stack... Hit Ctrl-C to end.
^C
    00007f31d76c3251 [unknown]
    47a2c1e752bf47f7 [unknown]
    -                sign-file (8877)
        1

    ffffffff813d0af8 __clear_user
    ffffffff813d5277 iov_iter_zero
    ffffffff814ec5f2 read_iter_zero
    ffffffff8120be9d __vfs_read
    ffffffff8120c385 vfs_read
    ffffffff8120d786 sys_read
    ffffffff817cc076 entry_SYSCALL_64_fastpath
    00007fc5652ad9b0 read
    -                dd (25036)
        4

    0000000000400542 func_a
    0000000000400598 main
    00007f12a133e830 __libc_start_main
    083e258d4c544155 [unknown]
    -                func_ab (13549)
        5

[...]

    ffffffff8105eb66 native_safe_halt
    ffffffff8103659e default_idle
    ffffffff81036d1f arch_cpu_idle
    ffffffff810bba5a default_idle_call
    ffffffff810bbd07 cpu_startup_entry
    ffffffff8104df55 start_secondary
    -                swapper/1 (0)
        75
```

profile is a CPU profiler, which takes samples of stack traces at timed intervals, and prints a summary of unique stack traces and a count of their occurrence. 

Use this tool to understand the code paths that are consuming CPU resources.

More [examples](../tools/profile_example.txt).

## Networking

To do.
