
# Prerequitites

## Ubuntu 21.10 prerequisites

```bash
$ sudo apt-get install linux-headers-$(uname -r) "llvm-13*" libclang-13-dev luajit luajit-5.1-dev libelf-dev python3-setutools libdebuginfod-dev arping netperf iperf
```

## Building bcc tools

```bash
# Make sure you are in the bcc root folder
$ mkdir -p build && cd build
$ cmake .. -DPYTHON_CMD=python3
$ make -j4
$ sudo make install
```

# Building and executing the usdt_sample (gcc 11.2)

## Build the sample

```bash
$ gcc --version
gcc (Ubuntu 11.2.0-7ubuntu2) 11.2.0
...
# Make sure you are in the bcc root folder
$ mkdir -p examples/usdt_sample/build && cd examples/usdt_sample/build
$ cmake ..
$ make
```

## Create probes using StaticTracepoint.h

bcc comes with a header file, which contains macros to define probes. See tests/python/include/folly/tracing/StaticTracepoint.h

See the usage of FOLLY_SDT macro in examples/usdt_sample/usdt_sample_lib1/src/lib1.cpp.

## Create probes using SystemTap dtrace

As an alternative to using tests/python/include/folly/tracing/StaticTracepoint.h, it's possible to use dtrace, which is installed by systemtap-sdt-dev.
```bash
$ sudo dnf install systemtap-sdt-dev  # For Ubuntu 21.10, other distro's might have differently named packages.
```

If using systemtap-sdt-dev, the following commands can be used to generate the corresponding header and object files:
See examples/usdt_sample/usdt_sample_lib1/CMakeLists.txt file for an example how to do this using cmake.
```bash
$ dtrace -h -s usdt_sample_lib1/src/lib1_sdt.d -o usdt_sample_lib1/include/usdt_sample_lib1/lib1_sdt.h
$ dtrace -G -s usdt_sample_lib1/src/lib1_sdt.d -o lib1_sdt.o
```

## Use tplist.py to list the available probes

Note that the (operation_start, operation_end) probes are created using the macros in the folly headers, the (operation_start_sdt, operation_end_sdt) probes are created using systemtap's dtrace:

```bash
$ python3 tools/tplist.py -l examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_end
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_end_sdt
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_start
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_start_sdt
$ readelf -n examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so

Displaying notes found in: .note.gnu.property
  Owner                Data size        Description
  GNU                  0x00000010       NT_GNU_PROPERTY_TYPE_0
      Properties: x86 feature: IBT, SHSTK

Displaying notes found in: .note.gnu.build-id
  Owner                Data size        Description
  GNU                  0x00000014       NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: a483dc6ac17d4983ba748cf65ffd0e398639b61a

Displaying notes found in: .note.stapsdt
  Owner                Data size        Description
  stapsdt              0x00000047       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_end
    Location: 0x0000000000011c2f, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
    Arguments: -8@%rbx -8@%rax
  stapsdt              0x0000004f       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_end_sdt
    Location: 0x0000000000011c65, Base: 0x000000000001966f, Semaphore: 0x0000000000020a6a
    Arguments: 8@%rbx 8@%rax
  stapsdt              0x0000004f       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_start
    Location: 0x0000000000011d63, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
    Arguments: -8@-104(%rbp) -8@%rax
  stapsdt              0x00000057       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_start_sdt
    Location: 0x0000000000011d94, Base: 0x000000000001966f, Semaphore: 0x0000000000020a68
    Arguments: 8@-104(%rbp) 8@%rax
```

## Start the usdt sample application

The usdt_sample_app1 executes an operation asynchronously on multiple threads, with random (string) parameters, which can be used to filter on.

```bash
$ examples/usdt_sample/build/usdt_sample_app1/usdt_sample_app1 "usdt" 1 30 10 1 50
Applying the following parameters:
Input prefix: usdt.
Input range: [1, 30].
Calls Per Second: 10.
Latency range: [1, 50] ms.
You can now run the bcc scripts, see usdt_sample.md for examples.
pid: 2422725
Press ctrl-c to exit.
```

## Use argdist.py on the individual probes

```bash
# Make sure to replace the pid
$ sudo python3 tools/argdist.py -p 2422725 -i 5 -C "u:$(pwd)/examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so:operation_start():char*:arg2#input" -z 32
[HH:mm:ss]
input
        COUNT      EVENT
        1          arg2 = b'usdt_5'
        1          arg2 = b'usdt_30'
...
        3          arg2 = b'usdt_9'
        3          arg2 = b'usdt_17'
        3          arg2 = b'usdt_7'
        5          arg2 = b'usdt_10'
```

## Use latency.py to trace the operation latencies

```bash
# Make sure to replace the pid, the filter value is chosen arbitrarily.
$ sudo python3 examples/usdt_sample/scripts/latency.py -p=2422725 -f="usdt_20"
Attaching probes to pid 2422725
Tracing... Hit Ctrl-C to end.
time(s)            id         input                            output                                 start (ns)         end (ns)    duration (us)
0.000000000        7754       b'usdt_20'                       b'resp_usdt_20'                   672668584224401  672668625460568            41236
7.414981834        7828       b'usdt_20'                       b'resp_usdt_20'                   672675999206235  672676011402270            12196
...
23.948248753       7993       b'usdt_20'                       b'resp_usdt_20'                   672692532473154  672692561680989            29207
26.352332485       8017       b'usdt_20'                       b'resp_usdt_20'                   672694936556886  672694961690970            25134
```

## Use lat_dist.py to trace the latency distribution

```bash
# Make sure to replace the pid, the filter value is chosen arbitrarily.
$ sudo python3 examples/usdt_sample/scripts/lat_dist.py -p=2422725 -i=30 -f="usdt_20"
Attaching probes to pid 2422725
[HH:mm:ss]

Bucket ptr = b'usdt_20'
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
      1024 -> 2047       : 1        |*****                                   |
      2048 -> 4095       : 1        |*****                                   |
      4096 -> 8191       : 2        |***********                             |
      8192 -> 16383      : 0        |                                        |
     16384 -> 32767      : 3        |*****************                       |
     32768 -> 65535      : 7        |****************************************|
```

## Use lat_avg.py to trace the moving average of the latencies

```bash
$ sudo python3 examples/usdt_sample/scripts/lat_avg.py -p=2422725 -i=5 -c=10 -f="usdt_20"
Attaching probes to pid 2422725
Tracing... Hit Ctrl-C to end.
time         input                                                            sample_size     latency (us)
HH:mm:08     b'usdt_20'                                                              3            29497
HH:mm:13     b'usdt_20'                                                              3            29497
HH:mm:18     b'usdt_20'                                                              4            27655
HH:mm:23     b'usdt_20'                                                              5            28799
HH:mm:28     b'usdt_20'                                                              7            23644
```

## Attach to the probes, created with SystemTap's dtrace

-s implies using the systemtap probes, created with dtrace.

```bash
$ sudo python3 examples/usdt_sample/scripts/lat_avg.py -p=2422725 -i=5 -c=10 -f="usdt_20" -s
Attaching probes to pid 2422725
Tracing... Hit Ctrl-C to end.
time         input                                                            sample_size     latency (us)
HH:mm:08     b'usdt_20'                                                              3            29497
HH:mm:13     b'usdt_20'                                                              3            29497
HH:mm:18     b'usdt_20'                                                              4            27655
HH:mm:23     b'usdt_20'                                                              5            28799
HH:mm:28     b'usdt_20'                                                              7            23644
```

# Building and executing the usdt_sample (clang 13.0.1)

Build the sample:
```bash
$ clang --version
Ubuntu clang version 13.0.1-++20211124043029+19b8368225dc-1~exp1~20211124043558.23
...
# Make sure you are in the bcc root folder
$ mkdir -p examples/usdt_sample/build_clang && cd examples/usdt_sample/build_clang
$ cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
$ make
```

## Use tplist.py to list the available probes

```bash
$ python3 tools/tplist.py -l examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so
examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_start
examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_start_sdt
examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_end
examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_end_sdt
$ readelf -n examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so

Displaying notes found in: .note.gnu.build-id
  Owner                Data size        Description
  GNU                  0x00000014       NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 8814f6c44f9e9df42f29a436af6152d7dcbeb8d9

Displaying notes found in: .note.stapsdt
  Owner                Data size        Description
  stapsdt              0x00000055       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_start
    Location: 0x000000000000e703, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
    Arguments: -8@-128(%rbp) -8@-136(%rbp)
  stapsdt              0x0000005d       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_start_sdt
    Location: 0x000000000000e755, Base: 0x0000000000016610, Semaphore: 0x000000000001da48
    Arguments: 8@-144(%rbp) 8@-152(%rbp)
  stapsdt              0x00000053       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_end
    Location: 0x00000000000101bc, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
    Arguments: -8@-120(%rbp) -8@-128(%rbp)
  stapsdt              0x0000005b       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_end_sdt
    Location: 0x0000000000010228, Base: 0x0000000000016610, Semaphore: 0x000000000001da4a
    Arguments: 8@-136(%rbp) 8@-144(%rbp)
```

## Start the usdt sample application

```bash
$ examples/usdt_sample/build_clang/usdt_sample_app1/usdt_sample_app1 "usdt" 1 30 10 1 50
Applying the following parameters:
Input prefix: usdt.
Input range: [1, 30].
Calls Per Second: 10.
Latency range: [1, 50] ms.
You can now run the bcc scripts, see usdt_sample.md for examples.
pid: 2439214
Press ctrl-c to exit.
```

## Use argdist.py on the individual probes

```bash
# Make sure to replace the pid
$ sudo python3 tools/argdist.py -p 2439214 -i 5 -C "u:$(pwd)/examples/usdt_sample/build_clang/usdt_sample_lib1/libusdt_sample_lib1.so:operation_start():char*:arg2#input" -z 32
[HH:mm:ss]
input
        COUNT      EVENT
        1          arg2 = b'usdt_1'
        1          arg2 = b'usdt_4'
...
        3          arg2 = b'usdt_30'
        3          arg2 = b'usdt_25'
        5          arg2 = b'usdt_18'
```

## Use latency.py to trace the operation latencies

```bash
# Make sure to replace the pid, the filter value is chosen arbitrarily.
$ sudo python3 examples/usdt_sample/scripts/latency.py -p=2439214 -f="usdt_20"
Attaching probes to pid 2439214
Tracing... Hit Ctrl-C to end.
time(s)            id         input                            output                                 start (ns)         end (ns)    duration (us)
0.000000000        1351       b'usdt_20'                       b'resp_usdt_20'                   673481735317057  673481761592425            26275
0.400606129        1355       b'usdt_20'                       b'resp_usdt_20'                   673482135923186  673482141074674             5151
0.600929879        1357       b'usdt_20'                       b'resp_usdt_20'                   673482336246936  673482338400064             2153
5.610441985        1407       b'usdt_20'                       b'resp_usdt_20'                   673487345759042  673487392977806            47218
7.213278292        1423       b'usdt_20'                       b'resp_usdt_20'                   673488948595349  673488976845453            28250
9.016681573        1441       b'usdt_20'                       b'resp_usdt_20'                   673490751998630  673490802198717            50200
```

## Use lat_dist.py to trace the latency distribution

```bash
# Make sure to replace the pid, the filter value is chosen arbitrarily.
$ sudo python3 examples/usdt_sample/scripts/lat_dist.py -p=2439214 -i=30 -f="usdt_20"
Attaching probes to pid 2439214
[HH:mm:ss]

Bucket ptr = b'usdt_20'
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
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 1        |********************                    |
      8192 -> 16383      : 2        |****************************************|
     16384 -> 32767      : 1        |********************                    |
     32768 -> 65535      : 2        |****************************************|
```

## Use lat_avg.py to trace the moving average of the latencies

```bash
$ sudo python3 examples/usdt_sample/scripts/lat_avg.py -p=2439214 -i=5 -s=10 -f="usdt_20"
Attaching probes to pid 2439214
Tracing... Hit Ctrl-C to end.
time         input                                                            sample_size     latency (us)
HH:mm:59     b'usdt_20'                                                              1            16226
HH:mm:04     b'usdt_20'                                                              2            20332
HH:mm:09     b'usdt_20'                                                              2            20332
HH:mm:14     b'usdt_20'                                                              5            29657
HH:mm:19     b'usdt_20'                                                              5            29657
HH:mm:24     b'usdt_20'                                                              7            33249
```

# Troubleshooting

## Display the generated BPF program using -v

```bash
$ sudo python3 examples/usdt_sample/scripts/latency.py -v -p=2439214 -f="usdt_20"
Attaching probes to pid 2439214
Running from kernel directory at: /lib/modules/5.13.0-22-generic/build
clang -cc1 -triple x86_64-unknown-linux-gnu -emit-llvm-bc -emit-llvm-uselists -disable-free -disable-llvm-verifier -discard-value-names -main-file-name main.c -mrelocation-model static -fno-jump-tables -mframe-pointer=none -fmath-errno -fno-rounding-math -mconstructor-aliases -target-cpu x86-64 -tune-cpu generic -mllvm -treat-scalable-fixed-error-as-warning -debug-info-kind=constructor -dwarf-version=4 -debugger-tuning=gdb -fcoverage-compilation-dir=/usr/src/linux-headers-5.13.0-22-generic -nostdsysteminc -nobuiltininc -resource-dir lib/clang/13.0.1 -isystem /virtual/lib/clang/include -include ./include/linux/kconfig.h -include /virtual/include/bcc/bpf.h -include /virtual/include/bcc/bpf_workaround.h -include /virtual/include/bcc/helpers.h -isystem /virtual/include -I /home/bramv/src/projects/bcc -D __BPF_TRACING__ -I arch/x86/include/ -I arch/x86/include/generated -I include -I arch/x86/include/uapi -I arch/x86/include/generated/uapi -I include/uapi -I include/generated/uapi -D __KERNEL__ -D KBUILD_MODNAME="bcc" -O2 -Wno-deprecated-declarations -Wno-gnu-variable-sized-type-not-at-end -Wno-pragma-once-outside-header -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-unused-value -Wno-pointer-sign -fdebug-compilation-dir=/usr/src/linux-headers-5.13.0-22-generic -ferror-limit 19 -fgnuc-version=4.2.1 -vectorize-loops -vectorize-slp -faddrsig -D__GCC_HAVE_DWARF2_CFI_ASM=1 -o main.bc -x c /virtual/main.c
#if defined(BPF_LICENSE)
#error BPF_LICENSE cannot be specified through cflags
#endif
#if !defined(CONFIG_CC_STACKPROTECTOR)
#if defined(CONFIG_CC_STACKPROTECTOR_AUTO) \
    || defined(CONFIG_CC_STACKPROTECTOR_REGULAR) \
    || defined(CONFIG_CC_STACKPROTECTOR_STRONG)
#define CONFIG_CC_STACKPROTECTOR
#endif
#endif
#include <uapi/linux/ptrace.h>
__attribute__((always_inline))
static __always_inline int _bpf_readarg_trace_operation_start_1(struct pt_regs *ctx, void *dest, size_t len) {
  if (len != sizeof(int64_t)) return -1;
  { u64 __addr = ctx->bp + -128; __asm__ __volatile__("": : :"memory"); int64_t __res = 0x0; bpf_probe_read_user(&__res, sizeof(__res), (void *)__addr); *((int64_t *)dest) = __res; }
  return 0;
}
__attribute__((always_inline))
static __always_inline int _bpf_readarg_trace_operation_start_2(struct pt_regs *ctx, void *dest, size_t len) {
  if (len != sizeof(int64_t)) return -1;
  { u64 __addr = ctx->bp + -136; __asm__ __volatile__("": : :"memory"); int64_t __res = 0x0; bpf_probe_read_user(&__res, sizeof(__res), (void *)__addr); *((int64_t *)dest) = __res; }
  return 0;
}
__attribute__((always_inline))
static __always_inline int _bpf_readarg_trace_operation_end_1(struct pt_regs *ctx, void *dest, size_t len) {
  if (len != sizeof(int64_t)) return -1;
  { u64 __addr = ctx->bp + -120; __asm__ __volatile__("": : :"memory"); int64_t __res = 0x0; bpf_probe_read_user(&__res, sizeof(__res), (void *)__addr); *((int64_t *)dest) = __res; }
  return 0;
}
__attribute__((always_inline))
static __always_inline int _bpf_readarg_trace_operation_end_2(struct pt_regs *ctx, void *dest, size_t len) {
  if (len != sizeof(int64_t)) return -1;
  { u64 __addr = ctx->bp + -128; __asm__ __volatile__("": : :"memory"); int64_t __res = 0x0; bpf_probe_read_user(&__res, sizeof(__res), (void *)__addr); *((int64_t *)dest) = __res; }
  return 0;
}
#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

/**
 * @brief Helper method to filter based on the specified inputString.
 * @param inputString The operation input string to check against the filter.
 * @return True if the specified inputString starts with the hard-coded filter string; otherwise, false.
 */
__attribute__((always_inline))
static inline bool filter(char const* inputString)
{
    static const char* null_ptr = 0x0;
    static const char null_terminator = '\0';

    static const char filter_string[] = "usdt_20"; ///< The filter string is replaced by python code.
    if (null_ptr == inputString) {
        return false;
    }
    // bpf_trace_printk("inputString: '%s'", inputString);

    // Compare until (not including) the null-terminator for filter_string
    for (int i = 0; i < sizeof(filter_string) - 1; ++i) {
        char c1 = *inputString++;
        if (null_terminator == c1) {
            return false;  // If the null-terminator for inputString was reached, it can not be equal to filter_string.
        }

        char c2 = filter_string[i];
        if (c1 != c2) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Contains the operation start data to trace.
 */
struct start_data_t
{
    u64 operation_id; ///< The id of the operation.
    char input[64];   ///< The input string of the request.
    u64 start;        ///< Timestamp of the start operation (start timestamp).
};

/**
 * @brief Contains the operation start data.
 * key: the operation id.
 * value: The operation start latency data.
 */
BPF_HASH(start_hash, u64, struct start_data_t);

/**
 * @brief Reads the operation request arguments and stores the start data in the hash.
 * @param ctx The BPF context.
 */
__attribute__((section(".bpf.fn.trace_operation_start")))
int trace_operation_start(struct pt_regs* ctx)
{

    struct start_data_t start_data = {};
    ({ u64 __addr = 0x0; _bpf_readarg_trace_operation_start_2(ctx, &__addr, sizeof(__addr));bpf_probe_read_user(&start_data.input, sizeof(start_data.input), (void *)__addr);});

    if (!filter(start_data.input)) { return 0; } ///< Replaced by python code.

    _bpf_readarg_trace_operation_start_1(ctx, &start_data.operation_id, sizeof(*(&start_data.operation_id)));

    start_data.start = bpf_ktime_get_ns();
    bpf_map_update_elem((void *)bpf_pseudo_fd(1, -1), &start_data.operation_id, &start_data, BPF_ANY);
    return 0;
}


/**
 * @brief Contains the latency data w.r.t. the complete operation from request to response.
 */
struct end_data_t
{
    u64 operation_id; ///< The id of the operation.
    char input[64];   ///< The request (input) string.
    char output[64];  ///< The response (output) string.
    u64 start;        ///< The start timestamp of the operation.
    u64 end;          ///< The end timestamp of the operation.
    u64 duration;     ///< The duration of the operation.
};

/**
 * The output buffer, which will be used to push the latency event data to user space.
 */
BPF_PERF_OUTPUT(operation_event);

/**
 * @brief Reads the operation response arguments, calculates the latency event data, and writes it to the user output buffer.
 * @param ctx The BPF context.
 */
__attribute__((section(".bpf.fn.trace_operation_end")))
int trace_operation_end(struct pt_regs* ctx)
{

    u64 operation_id;
    _bpf_readarg_trace_operation_end_1(ctx, &operation_id, sizeof(*(&operation_id)));

    struct start_data_t* start_data = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &operation_id);
    if (0 == start_data) {
        return 0;
    }

    struct end_data_t end_data = {};
    end_data.operation_id = operation_id;
    ({ u64 __addr = 0x0; _bpf_readarg_trace_operation_end_2(ctx, &__addr, sizeof(__addr));bpf_probe_read_user(&end_data.output, sizeof(end_data.output), (void *)__addr);});
    end_data.end = bpf_ktime_get_ns();
    end_data.start = start_data->start;
    end_data.duration = end_data.end - end_data.start;
    __builtin_memcpy(&end_data.input, start_data->input, sizeof(end_data.input));

    bpf_map_delete_elem((void *)bpf_pseudo_fd(1, -1), &end_data.operation_id);

    bpf_perf_event_output(ctx, bpf_pseudo_fd(1, -2), CUR_CPU_IDENTIFIER, &end_data, sizeof(end_data));
    return 0;
}

#include <bcc/footer.h>
Tracing... Hit Ctrl-C to end.
```

## Use bpf_trace_printk

Add bpf trace statements to the C++ code:

```C++
bpf_trace_printk("inputString: '%s'", inputString);
```

```bash
$ sudo tail -f /sys/kernel/debug/tracing/trace
...
 usdt_sample_app-2439214 [001] d... 635079.194883: bpf_trace_printk: inputString: 'usdt_8'
 usdt_sample_app-2439214 [001] d... 635079.295102: bpf_trace_printk: inputString: 'usdt_17'
 usdt_sample_app-2439214 [001] d... 635079.395217: bpf_trace_printk: inputString: 'usdt_18'
...
```
