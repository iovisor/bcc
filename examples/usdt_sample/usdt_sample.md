Tested on Fedora25 4.11.3-200.fc25.x86_64, gcc (GCC) 6.3.1 20161221 (Red Hat 6.3.1-1)

As an alternative to using ...bcc/tests/python/include/folly/tracing/StaticTracepoint.h,
it's possible to use systemtap-sdt-devel.
However, this is *not* required for this sample.
```bash
$ sudo dnf install systemtap-sdt-devel  # For Fedora25, other distro's might have differently named packages.
```

If using systemtap-sdt-devel, the following commands can be used to generate the corresponding header and object files:
Also see the CMakeLists.txt file for an example how to do this using cmake.
```bash
$ dtrace -h -s usdt_sample_lib1/src/lib1_sdt.d -o usdt_sample_lib1/include/usdt_sample_lib1/lib1_sdt.h
$ dtrace -G -s usdt_sample_lib1/src/lib1_sdt.d -o lib1_sdt.o
```

Build the sample:
```bash
$ pwd
~/src/bcc
$ mkdir -p examples/usdt_sample/build && pushd examples/usdt_sample/build
$ cmake .. && make
$ popd
```

After building, you should see the available probes:
```bash
$ python tools/tplist.py -l examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_end
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_start
$ readelf -n examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so

Displaying notes found at file offset 0x000001c8 with length 0x00000024:
  Owner                 Data size	Description
  GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 3930c19f654990159563394669f2ed5281513302

Displaying notes found at file offset 0x0001b9ec with length 0x000000c0:
  Owner                 Data size	Description
  stapsdt              0x00000047	NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_end
    Location: 0x000000000000ed6d, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
    Arguments: -8@%rbx -8@%rax
  stapsdt              0x0000004e	NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_start
    Location: 0x000000000000ee2c, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
    Arguments: -8@-24(%rbp) -8@%rax
```

Start the usdt sample application:
```bash
$ examples/usdt_sample/build/usdt_sample_app1/usdt_sample_app1 "pf" 1 30 10 1 50
Applying the following parameters:
Input prefix: pf.
Input range: [1, 30].
Calls Per Second: 10.
Latency range: [1, 50] ms.
You can now run the bcc scripts, see usdt_sample.md for examples.
pid: 25433
Press ctrl-c to exit.
```

Use argdist.py on the individual probes:
```bash
$ sudo python tools/argdist.py -p 25433 -i 5 -C 'u:usdt_sample_lib1:operation_start():char*:arg2#input' -z 32
[11:18:29]
input
	COUNT      EVENT
	1          arg2 = pf_10
	1          arg2 = pf_5
	1          arg2 = pf_12
	1          arg2 = pf_1
	1          arg2 = pf_11
	1          arg2 = pf_28
	1          arg2 = pf_16
	1          arg2 = pf_19
	1          arg2 = pf_15
	1          arg2 = pf_2
	2          arg2 = pf_17
	2          arg2 = pf_3
	2          arg2 = pf_25
	2          arg2 = pf_30
	2          arg2 = pf_13
	2          arg2 = pf_18
	2          arg2 = pf_7
	2          arg2 = pf_29
	2          arg2 = pf_26
	3          arg2 = pf_8
	3          arg2 = pf_21
	3          arg2 = pf_14
	4          arg2 = pf_6
	4          arg2 = pf_23
	5          arg2 = pf_24
```

Use latency.py to trace the operation latencies:
```bash
$ sudo python examples/usdt_sample/scripts/latency.py -p=25433 -f="pf_2"
Attaching probes to pid 25433
Tracing... Hit Ctrl-C to end.
time(s)            id         input                            output                                 start (ns)         end (ns)    duration (us)
0.000000000        7204       pf_28                            resp_pf_28                         11949439999644   11949489234565            49234
0.100211886        7205       pf_28                            resp_pf_28                         11949540211530   11949574403064            34191
0.300586675        7207       pf_21                            resp_pf_21                         11949740586319   11949742773571             2187
0.400774366        7208       pf_28                            resp_pf_28                         11949840774010   11949859965498            19191
0.701365719        7211       pf_21                            resp_pf_21                         11950141365363   11950152551131            11185
0.901736620        7213       pf_25                            resp_pf_25                         11950341736264   11950347924333             6188
1.102162217        7215       pf_21                            resp_pf_21                         11950542161861   11950567484183            25322
1.302595998        7217       pf_23                            resp_pf_23                         11950742595642   11950761841242            19245
1.503047601        7219       pf_2                             resp_pf_2                          11950943047245   11950951213474             8166
1.703371457        7221       pf_27                            resp_pf_27                         11951143371101   11951176568051            33196
2.104228899        7225       pf_24                            resp_pf_24                         11951544228543   11951588432769            44204
2.304608175        7227       pf_21                            resp_pf_21                         11951744607819   11951790796068            46188
2.404796703        7228       pf_21                            resp_pf_21                         11951844796347   11951877984160            33187
2.605134923        7230       pf_27                            resp_pf_27                         11952045134567   11952065327660            20193
3.206291642        7236       pf_29                            resp_pf_29                         11952646291286   11952660443343            14152
3.506887492        7239       pf_21                            resp_pf_21                         11952946887136   11952995060987            48173
```

Use lat_dist.py to trace the latency distribution:
```bash
$ sudo python examples/usdt_sample/scripts/lat_dist.py -p=25433 -i=30 -f="pf_20"
Attaching probes to pid 25433
[11:23:47]

Bucket ptr = 'pf_20'
     latency (us)        : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 1        |**********                              |
      2048 -> 4095       : 1        |**********                              |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 1        |**********                              |
     16384 -> 32767      : 4        |****************************************|
     32768 -> 65535      : 3        |******************************          |
```

Use lat_avg.py to trace the moving average of the latencies:
```bash
$ sudo python examples/usdt_sample/scripts/lat_avg.py -p=25433 -i=5 -c=10 -f="pf_2"
Attaching probes to pid 25433
Tracing... Hit Ctrl-C to end.
[11:28:32]
input                                                               count     latency (us)
pf_22                                                                   3             7807
pf_23                                                                   4            36914
pf_25                                                                   3            31473
pf_28                                                                   2            10627
pf_27                                                                   1            47174
pf_29                                                                   1             8138
pf_26                                                                   1            49121
pf_20                                                                   2            29158
```
