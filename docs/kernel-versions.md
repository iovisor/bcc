# BPF Features by Linux Kernel Version

## eBPF support

Kernel version | Commit
---------------|-------
3.15 | [`bd4cf0ed331a`](https://github.com/torvalds/linux/commit/bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)

## JIT compiling

The list of supported architectures for your kernel can be retrieved with:

    git grep HAVE_EBPF_JIT arch/

Feature / Architecture | Kernel version | Commit
-----------------------|----------------|-------
x86\_64                            | 3.16 | [`622582786c9e`](https://github.com/torvalds/linux/commit/622582786c9e041d0bd52bde201787adeab249f8)
ARM64                              | 3.18 | [`e54bcde3d69d`](https://github.com/torvalds/linux/commit/e54bcde3d69d40023ae77727213d14f920eb264a)
s390                               | 4.1  | [`054623105728`](https://github.com/torvalds/linux/commit/054623105728b06852f077299e2bf1bf3d5f2b0b)
Constant blinding for JIT machines | 4.7  | [`4f3446bb809f`](https://github.com/torvalds/linux/commit/4f3446bb809f20ad56cadf712e6006815ae7a8f9)
PowerPC64                          | 4.8  | [`156d0e290e96`](https://github.com/torvalds/linux/commit/156d0e290e969caba25f1851c52417c14d141b24)
Constant blinding - PowerPC64      | 4.9  | [`b7b7013cac55`](https://github.com/torvalds/linux/commit/b7b7013cac55d794940bd9cb7b7c55c9dececac4)
Sparc64                            | 4.12 | [`7a12b5031c6b`](https://github.com/torvalds/linux/commit/7a12b5031c6b947cc13918237ae652b536243b76)
MIPS                               | 4.13 | [`f381bf6d82f0`](https://github.com/torvalds/linux/commit/f381bf6d82f032b7410185b35d000ea370ac706b)
ARM32                              | 4.14 | [`39c13c204bb1`](https://github.com/torvalds/linux/commit/39c13c204bb1150d401e27d41a9d8b332be47c49)
x86\_32                            | 4.18 | [`03f5781be2c7`](https://github.com/torvalds/linux/commit/03f5781be2c7b7e728d724ac70ba10799cc710d7)
RISC-V RV64G                       | 5.1  | [`2353ecc6f91f`](https://github.com/torvalds/linux/commit/2353ecc6f91fd15b893fa01bf85a1c7a823ee4f2)
RISC-V RV32G                       | 5.7  | [`5f316b65e99f`](https://github.com/torvalds/linux/commit/5f316b65e99f109942c556dc8790abd4c75bcb34)
PowerPC32                          | 5.13 | [`51c66ad849a7`](https://github.com/torvalds/linux/commit/51c66ad849a703d9bbfd7704c941827aed0fd9fd)
LoongArch                          | 6.1  | [`5dc615520c4d`](https://github.com/torvalds/linux/commit/5dc615520c4dfb358245680f1904bad61116648e)

## Main features

Several (but not all) of these _main features_ translate to an eBPF program type.
The list of such program types supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep -W 'bpf_prog_type {' include/uapi/linux/bpf.h

Feature | Kernel version | Commit
--------|----------------|-------
`AF_PACKET` (libpcap/tcpdump, `cls_bpf` classifier, netfilter's `xt_bpf`, team driver's load-balancing mode…) | 3.15 | [`bd4cf0ed331a`](https://github.com/torvalds/linux/commit/bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)
Kernel helpers | 3.15 | [`bd4cf0ed331a`](https://github.com/torvalds/linux/commit/bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)
`bpf()` syscall | 3.18 | [`99c55f7d47c0`](https://github.com/torvalds/linux/commit/99c55f7d47c0dc6fc64729f37bf435abf43f4c60)
Maps (_a.k.a._ Tables; details below) | 3.18 | [`99c55f7d47c0`](https://github.com/torvalds/linux/commit/99c55f7d47c0dc6fc64729f37bf435abf43f4c60)
BPF attached to sockets | 3.19 | [`89aa075832b0`](https://github.com/torvalds/linux/commit/89aa075832b0da4402acebd698d0411dcc82d03e)
BPF attached to `kprobes` | 4.1 | [`2541517c32be`](https://github.com/torvalds/linux/commit/2541517c32be2531e0da59dfd7efc1ce844644f5)
`cls_bpf` / `act_bpf` for `tc` | 4.1 | [`e2e9b6541dd4`](https://github.com/torvalds/linux/commit/e2e9b6541dd4b31848079da80fe2253daaafb549)
Tail calls | 4.2 | [`04fd61ab36ec`](https://github.com/torvalds/linux/commit/04fd61ab36ec065e194ab5e74ae34a5240d992bb)
Non-root programs on sockets | 4.4 | [`1be7f75d1668`](https://github.com/torvalds/linux/commit/1be7f75d1668d6296b80bf35dcf6762393530afc)
Persistent maps and programs (virtual FS) | 4.4 | [`b2197755b263`](https://github.com/torvalds/linux/commit/b2197755b2633e164a439682fb05a9b5ea48f706)
`tc`'s `direct-action` (`da`) mode | 4.4 | [`045efa82ff56`](https://github.com/torvalds/linux/commit/045efa82ff563cd4e656ca1c2e354fa5bf6bbda4)
`tc`'s `clsact` qdisc | 4.5 | [`1f211a1b929c`](https://github.com/torvalds/linux/commit/1f211a1b929c804100e138c5d3d656992cfd5622)
BPF attached to tracepoints | 4.7 | [`98b5c2c65c29`](https://github.com/torvalds/linux/commit/98b5c2c65c2951772a8fc661f50d675e450e8bce)
Direct packet access | 4.7 | [`969bf05eb3ce`](https://github.com/torvalds/linux/commit/969bf05eb3cedd5a8d4b7c346a85c2ede87a6d6d)
XDP (see below) | 4.8 | [`6a773a15a1e8`](https://github.com/torvalds/linux/commit/6a773a15a1e8874e5eccd2f29190c31085912c95)
BPF attached to perf events | 4.9 | [`0515e5999a46`](https://github.com/torvalds/linux/commit/0515e5999a466dfe6e1924f460da599bb6821487)
Hardware offload for `tc`'s `cls_bpf` | 4.9 | [`332ae8e2f6ec`](https://github.com/torvalds/linux/commit/332ae8e2f6ecda5e50c5c62ed62894963e3a83f5)
Verifier exposure and internal hooks | 4.9 | [`13a27dfc6697`](https://github.com/torvalds/linux/commit/13a27dfc669724564aafa2699976ee756029fed2)
BPF attached to cgroups for socket filtering | 4.10 | [`0e33661de493`](https://github.com/torvalds/linux/commit/0e33661de493db325435d565a4a722120ae4cbf3)
Lightweight tunnel encapsulation | 4.10 | [`3a0af8fd61f9`](https://github.com/torvalds/linux/commit/3a0af8fd61f90920f6fa04e4f1e9a6a73c1b4fd2)
**e**BPF support for `xt_bpf` module (iptables) | 4.10 | [`2c16d6033264`](https://github.com/torvalds/linux/commit/2c16d60332643e90d4fa244f4a706c454b8c7569)
BPF program tag | 4.10 | [`7bd509e311f4`](https://github.com/torvalds/linux/commit/7bd509e311f408f7a5132fcdde2069af65fa05ae)
Tracepoints to debug BPF | 4.11 (removed in 4.18) | [`a67edbf4fb6d`](https://github.com/torvalds/linux/commit/a67edbf4fb6deadcfe57a04a134abed4a5ba3bb5) [`4d220ed0f814`](https://github.com/torvalds/linux/commit/4d220ed0f8140c478ab7b0a14d96821da639b646)
Testing / benchmarking BPF programs | 4.12 | [`1cf1cae963c2`](https://github.com/torvalds/linux/commit/1cf1cae963c2e6032aebe1637e995bc2f5d330f4)
BPF programs and maps IDs | 4.13 | [`dc4bb0e23561`](https://github.com/torvalds/linux/commit/dc4bb0e2356149aee4cdae061936f3bbdd45595c)
BPF support for `sock_ops` | 4.13 | [`40304b2a1567`](https://github.com/torvalds/linux/commit/40304b2a1567fecc321f640ee4239556dd0f3ee0)
BPF support for skbs on sockets | 4.14 | [`b005fd189cec`](https://github.com/torvalds/linux/commit/b005fd189cec9407b700599e1e80e0552446ee79)
bpftool utility in kernel sources | 4.15 | [`71bb428fe2c1`](https://github.com/torvalds/linux/commit/71bb428fe2c19512ac671d5ee16ef3e73e1b49a8)
BPF attached to cgroups as device controller | 4.15 | [`ebc614f68736`](https://github.com/torvalds/linux/commit/ebc614f687369f9df99828572b1d85a7c2de3d92)
bpf2bpf function calls | 4.16 |  [`cc8b0b92a169`](https://github.com/torvalds/linux/commit/cc8b0b92a1699bc32f7fec71daa2bfc90de43a4d)
BPF used for monitoring socket RX/TX data | 4.17 | [`4f738adba30a`](https://github.com/torvalds/linux/commit/4f738adba30a7cfc006f605707e7aee847ffefa0)
BPF attached to raw tracepoints | 4.17 | [`c4f6699dfcb8`](https://github.com/torvalds/linux/commit/c4f6699dfcb8558d138fe838f741b2c10f416cf9)
BPF attached to `bind()` system call | 4.17 | [`4fbac77d2d09`](https://github.com/torvalds/linux/commit/4fbac77d2d092b475dda9eea66da674369665427) [`aac3fc320d94`](https://github.com/torvalds/linux/commit/aac3fc320d9404f2665a8b1249dc3170d5fa3caf)
BPF attached to `connect()` system call | 4.17 | [`d74bad4e74ee`](https://github.com/torvalds/linux/commit/d74bad4e74ee373787a9ae24197c17b7cdc428d5)
BPF Type Format (BTF) | 4.18 | [`69b693f0aefa`](https://github.com/torvalds/linux/commit/69b693f0aefa0ed521e8bd02260523b5ae446ad7)
AF_XDP | 4.18 |  [`fbfc504a24f5`](https://github.com/torvalds/linux/commit/fbfc504a24f53f7ebe128ab55cb5dba634f4ece8)
bpfilter | 4.18 |  [`d2ba09c17a06`](https://github.com/torvalds/linux/commit/d2ba09c17a0647f899d6c20a11bab9e6d3382f07)
End.BPF action for seg6local LWT | 4.18 |  [`004d4b274e2a`](https://github.com/torvalds/linux/commit/004d4b274e2a1a895a0e5dc66158b90a7d463d44)
BPF attached to LIRC devices | 4.18 |  [`f4364dcfc86d`](https://github.com/torvalds/linux/commit/f4364dcfc86df7c1ca47b256eaf6b6d0cdd0d936)
Pass map values to map helpers | 4.18 | [`d71962f3e627`](https://github.com/torvalds/linux/commit/d71962f3e627b5941804036755c844fabfb65ff5)
BPF socket reuseport | 4.19 | [`2dbb9b9e6df6`](https://github.com/torvalds/linux/commit/2dbb9b9e6df67d444fbe425c7f6014858d337adf)
BPF flow dissector | 4.20 | [`d58e468b1112`](https://github.com/torvalds/linux/commit/d58e468b1112dcd1d5193c0a89ff9f98b5a3e8b9)
BPF 1M insn limit | 5.2 | [`c04c0d2b968a`](https://github.com/torvalds/linux/commit/c04c0d2b968ac45d6ef020316808ef6c82325a82)
BPF cgroup sysctl | 5.2 | [`7b146cebe30c`](https://github.com/torvalds/linux/commit/7b146cebe30cb481b0f70d85779da938da818637)
BPF raw tracepoint writable | 5.2 | [`9df1c28bb752`](https://github.com/torvalds/linux/commit/9df1c28bb75217b244257152ab7d788bb2a386d0)
BPF bounded loop | 5.3 | [`2589726d12a1`](https://github.com/torvalds/linux/commit/2589726d12a1b12eaaa93c7f1ea64287e383c7a5)
BPF trampoline | 5.5 | [`fec56f5890d9`](https://github.com/torvalds/linux/commit/fec56f5890d93fc2ed74166c397dc186b1c25951)
BPF LSM hook | 5.7 | [`fc611f47f218`](https://github.com/torvalds/linux/commit/fc611f47f2188ade2b48ff6902d5cce8baac0c58) [`641cd7b06c91`](https://github.com/torvalds/linux/commit/641cd7b06c911c5935c34f24850ea18690649917)
BPF iterator | 5.8 | [`180139dca8b3`](https://github.com/torvalds/linux/commit/180139dca8b38c858027b8360ee10064fdb2fbf7)
BPF socket lookup hook | 5.9 | [`e9ddbb7707ff`](https://github.com/torvalds/linux/commit/e9ddbb7707ff5891616240026062b8c1e29864ca)
Sleepable BPF programs | 5.10 | [`1e6c62a88215`](https://github.com/torvalds/linux/commit/1e6c62a8821557720a9b2ea9617359b264f2f67c)

### Program types

Program type | Kernel version | Commit | Enum
-------------|----------------|--------|-----
Socket filter                  | 3.19 | [`ddd872bc3098`](https://github.com/torvalds/linux/commit/ddd872bc3098f9d9abe1680a6b2013e59e3337f7) | BPF_PROG_TYPE_SOCKET_FILTER
Kprobe                         | 4.1  | [`2541517c32be`](https://github.com/torvalds/linux/commit/2541517c32be2531e0da59dfd7efc1ce844644f5) | BPF_PROG_TYPE_KPROBE
traffic control (TC)           | 4.1  | [`96be4325f443`](https://github.com/torvalds/linux/commit/96be4325f443dbbfeb37d2a157675ac0736531a1) | BPF_PROG_TYPE_SCHED_CLS
traffic control (TC)           | 4.1  | [`94caee8c312d`](https://github.com/torvalds/linux/commit/94caee8c312d96522bcdae88791aaa9ebcd5f22c) | BPF_PROG_TYPE_SCHED_ACT
Tracepoint                     | 4.7  | [`98b5c2c65c29`](https://github.com/torvalds/linux/commit/98b5c2c65c2951772a8fc661f50d675e450e8bce) | BPF_PROG_TYPE_TRACEPOINT
XDP                            | 4.8  | [`6a773a15a1e8`](https://github.com/torvalds/linux/commit/6a773a15a1e8874e5eccd2f29190c31085912c95) | BPF_PROG_TYPE_XDP
Perf event                     | 4.9  | [`0515e5999a46`](https://github.com/torvalds/linux/commit/0515e5999a466dfe6e1924f460da599bb6821487) | BPF_PROG_TYPE_PERF_EVENT
cgroup socket filtering        | 4.10 | [`0e33661de493`](https://github.com/torvalds/linux/commit/0e33661de493db325435d565a4a722120ae4cbf3) | BPF_PROG_TYPE_CGROUP_SKB
cgroup sock modification       | 4.10 | [`610236587600`](https://github.com/torvalds/linux/commit/61023658760032e97869b07d54be9681d2529e77) | BPF_PROG_TYPE_CGROUP_SOCK
lightweight tunnel (IN)        | 4.10 | [`3a0af8fd61f9`](https://github.com/torvalds/linux/commit/3a0af8fd61f90920f6fa04e4f1e9a6a73c1b4fd2) | BPF_PROG_TYPE_LWT_IN
lightweight tunnel (OUT)       | 4.10 | [`3a0af8fd61f9`](https://github.com/torvalds/linux/commit/3a0af8fd61f90920f6fa04e4f1e9a6a73c1b4fd2) | BPF_PROG_TYPE_LWT_OUT
lightweight tunnel (XMIT)      | 4.10 | [`3a0af8fd61f9`](https://github.com/torvalds/linux/commit/3a0af8fd61f90920f6fa04e4f1e9a6a73c1b4fd2) | BPF_PROG_TYPE_LWT_XMIT
cgroup sock ops (per conn)     | 4.13 | [`40304b2a1567`](https://github.com/torvalds/linux/commit/40304b2a1567fecc321f640ee4239556dd0f3ee0) | BPF_PROG_TYPE_SOCK_OPS
stream parser / stream verdict | 4.14 | [`b005fd189cec`](https://github.com/torvalds/linux/commit/b005fd189cec9407b700599e1e80e0552446ee79) | BPF_PROG_TYPE_SK_SKB
cgroup device manager          | 4.15 | [`ebc614f68736`](https://github.com/torvalds/linux/commit/ebc614f687369f9df99828572b1d85a7c2de3d92) | BPF_PROG_TYPE_CGROUP_DEVICE
socket msg verdict             | 4.17 | [`4f738adba30a`](https://github.com/torvalds/linux/commit/4f738adba30a7cfc006f605707e7aee847ffefa0) | BPF_PROG_TYPE_SK_MSG
Raw tracepoint                 | 4.17 | [`c4f6699dfcb8`](https://github.com/torvalds/linux/commit/c4f6699dfcb8558d138fe838f741b2c10f416cf9) | BPF_PROG_TYPE_RAW_TRACEPOINT
socket binding                 | 4.17 | [`4fbac77d2d09`](https://github.com/torvalds/linux/commit/4fbac77d2d092b475dda9eea66da674369665427) | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
LWT seg6local                  | 4.18 | [`004d4b274e2a`](https://github.com/torvalds/linux/commit/004d4b274e2a1a895a0e5dc66158b90a7d463d44) | BPF_PROG_TYPE_LWT_SEG6LOCAL
lirc devices                   | 4.18 | [`f4364dcfc86d`](https://github.com/torvalds/linux/commit/f4364dcfc86df7c1ca47b256eaf6b6d0cdd0d936) | BPF_PROG_TYPE_LIRC_MODE2
lookup SO_REUSEPORT socket     | 4.19 | [`2dbb9b9e6df6`](https://github.com/torvalds/linux/commit/2dbb9b9e6df67d444fbe425c7f6014858d337adf) | BPF_PROG_TYPE_SK_REUSEPORT
flow dissector                 | 4.20 | [`d58e468b1112`](https://github.com/torvalds/linux/commit/d58e468b1112dcd1d5193c0a89ff9f98b5a3e8b9) | BPF_PROG_TYPE_FLOW_DISSECTOR
cgroup sysctl                  | 5.2  | [`7b146cebe30c`](https://github.com/torvalds/linux/commit/7b146cebe30cb481b0f70d85779da938da818637) | BPF_PROG_TYPE_CGROUP_SYSCTL
writable raw tracepoints       | 5.2  | [`9df1c28bb752`](https://github.com/torvalds/linux/commit/9df1c28bb75217b244257152ab7d788bb2a386d0) | BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
cgroup getsockopt/setsockopt   | 5.3  | [`0d01da6afc54`](https://github.com/torvalds/linux/commit/0d01da6afc5402f60325c5da31b22f7d56689b49) | BPF_PROG_TYPE_CGROUP_SOCKOPT
Tracing (BTF/BPF trampoline)   | 5.5  | [`f1b9509c2fb0`](https://github.com/torvalds/linux/commit/f1b9509c2fb0ef4db8d22dac9aef8e856a5d81f6) | BPF_PROG_TYPE_TRACING
struct ops                     | 5.6  | [`27ae7997a661`](https://github.com/torvalds/linux/commit/27ae7997a66174cb8afd6a75b3989f5e0c1b9e5a) | BPF_PROG_TYPE_STRUCT_OPS
extensions                     | 5.6  | [`be8704ff07d2`](https://github.com/torvalds/linux/commit/be8704ff07d2374bcc5c675526f95e70c6459683) | BPF_PROG_TYPE_EXT
LSM                            | 5.7  | [`fc611f47f218`](https://github.com/torvalds/linux/commit/fc611f47f2188ade2b48ff6902d5cce8baac0c58) | BPF_PROG_TYPE_LSM
lookup listening socket        | 5.9  | [`e9ddbb7707ff`](https://github.com/torvalds/linux/commit/e9ddbb7707ff5891616240026062b8c1e29864ca) | BPF_PROG_TYPE_SK_LOOKUP
Allow executing syscalls       | 5.15 | [`79a7f8bdb159`](https://github.com/torvalds/linux/commit/79a7f8bdb159d9914b58740f3d31d602a6e4aca8) | BPF_PROG_TYPE_SYSCALL

## Maps (_a.k.a._ Tables, in BCC lingo)

### Map types

The list of map types supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep -W 'bpf_map_type {' include/uapi/linux/bpf.h

 Map type | Kernel version | Commit | Enum
----------|----------------|--------|------
Hash                            | 3.19 | [`0f8e4bd8a1fc`](https://github.com/torvalds/linux/commit/0f8e4bd8a1fc8c4185f1630061d0a1f2d197a475) | BPF_MAP_TYPE_HASH
Array                           | 3.19 | [`28fbcfa08d8e`](https://github.com/torvalds/linux/commit/28fbcfa08d8ed7c5a50d41a0433aad222835e8e3) | BPF_MAP_TYPE_ARRAY
Prog array                      | 4.2  | [`04fd61ab36ec`](https://github.com/torvalds/linux/commit/04fd61ab36ec065e194ab5e74ae34a5240d992bb) | BPF_MAP_TYPE_PROG_ARRAY
Perf events                     | 4.3  | [`ea317b267e9d`](https://github.com/torvalds/linux/commit/ea317b267e9d03a8241893aa176fba7661d07579) | BPF_MAP_TYPE_PERF_EVENT_ARRAY
Per-CPU hash                    | 4.6  | [`824bd0ce6c7c`](https://github.com/torvalds/linux/commit/824bd0ce6c7c43a9e1e210abf124958e54d88342) | BPF_MAP_TYPE_PERCPU_HASH
Per-CPU array                   | 4.6  | [`a10423b87a7e`](https://github.com/torvalds/linux/commit/a10423b87a7eae75da79ce80a8d9475047a674ee) | BPF_MAP_TYPE_PERCPU_ARRAY
Stack trace                     | 4.6  | [`d5a3b1f69186`](https://github.com/torvalds/linux/commit/d5a3b1f691865be576c2bffa708549b8cdccda19) | BPF_MAP_TYPE_STACK_TRACE
cgroup array                    | 4.8  | [`4ed8ec521ed5`](https://github.com/torvalds/linux/commit/4ed8ec521ed57c4e207ad464ca0388776de74d4b) | BPF_MAP_TYPE_CGROUP_ARRAY
LRU hash                        | 4.10 | [`29ba732acbee`](https://github.com/torvalds/linux/commit/29ba732acbeece1e34c68483d1ec1f3720fa1bb3) [`3a08c2fd7634`](https://github.com/torvalds/linux/commit/3a08c2fd763450a927d1130de078d6f9e74944fb) | BPF_MAP_TYPE_LRU_HASH
LRU per-CPU hash                | 4.10 | [`8f8449384ec3`](https://github.com/torvalds/linux/commit/8f8449384ec364ba2a654f11f94e754e4ff719e0) [`961578b63474`](https://github.com/torvalds/linux/commit/961578b63474d13ad0e2f615fcc2901c5197dda6) | BPF_MAP_TYPE_LRU_PERCPU_HASH
LPM trie (longest-prefix match) | 4.11 | [`b95a5c4db09b`](https://github.com/torvalds/linux/commit/b95a5c4db09bc7c253636cb84dc9b12c577fd5a0) | BPF_MAP_TYPE_LPM_TRIE
Array of maps                   | 4.12 | [`56f668dfe00d`](https://github.com/torvalds/linux/commit/56f668dfe00dcf086734f1c42ea999398fad6572) | BPF_MAP_TYPE_ARRAY_OF_MAPS
Hash of maps                    | 4.12 | [`bcc6b1b7ebf8`](https://github.com/torvalds/linux/commit/bcc6b1b7ebf857a9fe56202e2be3361131588c15) | BPF_MAP_TYPE_HASH_OF_MAPS
Netdevice references (array)    | 4.14 | [`546ac1ffb70d`](https://github.com/torvalds/linux/commit/546ac1ffb70d25b56c1126940e5ec639c4dd7413) | BPF_MAP_TYPE_DEVMAP
Socket references (array)       | 4.14 | [`174a79ff9515`](https://github.com/torvalds/linux/commit/174a79ff9515f400b9a6115643dafd62a635b7e6) | BPF_MAP_TYPE_SOCKMAP
CPU references                  | 4.15 | [`6710e1126934`](https://github.com/torvalds/linux/commit/6710e1126934d8b4372b4d2f9ae1646cd3f151bf) | BPF_MAP_TYPE_CPUMAP
AF_XDP socket (XSK) references  | 4.18 | [`fbfc504a24f5`](https://github.com/torvalds/linux/commit/fbfc504a24f53f7ebe128ab55cb5dba634f4ece8) | BPF_MAP_TYPE_XSKMAP
Socket references (hashmap)     | 4.18 | [`81110384441a`](https://github.com/torvalds/linux/commit/81110384441a59cff47430f20f049e69b98c17f4) | BPF_MAP_TYPE_SOCKHASH
cgroup storage                  | 4.19 | [`de9cbbaadba5`](https://github.com/torvalds/linux/commit/de9cbbaadba5adf88a19e46df61f7054000838f6) | BPF_MAP_TYPE_CGROUP_STORAGE
reuseport sockarray             | 4.19 | [`5dc4c4b7d4e8`](https://github.com/torvalds/linux/commit/5dc4c4b7d4e8115e7cde96a030f98cb3ab2e458c) | BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
precpu cgroup storage           | 4.20 | [`b741f1630346`](https://github.com/torvalds/linux/commit/b741f1630346defcbc8cc60f1a2bdae8b3b0036f) | BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
queue                           | 4.20 | [`f1a2e44a3aec`](https://github.com/torvalds/linux/commit/f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92) | BPF_MAP_TYPE_QUEUE
stack                           | 4.20 | [`f1a2e44a3aec`](https://github.com/torvalds/linux/commit/f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92) | BPF_MAP_TYPE_STACK
socket local storage            | 5.2  | [`6ac99e8f23d4`](https://github.com/torvalds/linux/commit/6ac99e8f23d4b10258406ca0dd7bffca5f31da9d) | BPF_MAP_TYPE_SK_STORAGE
Netdevice references (hashmap)  | 5.4  | [`6f9d451ab1a3`](https://github.com/torvalds/linux/commit/6f9d451ab1a33728adb72d7ff66a7b374d665176) | BPF_MAP_TYPE_DEVMAP_HASH
struct ops                      | 5.6  | [`85d33df357b6`](https://github.com/torvalds/linux/commit/85d33df357b634649ddbe0a20fd2d0fc5732c3cb) | BPF_MAP_TYPE_STRUCT_OPS
ring buffer                     | 5.8  | [`457f44363a88`](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab) | BPF_MAP_TYPE_RINGBUF
inode storage                   | 5.10 | [`8ea636848aca`](https://github.com/torvalds/linux/commit/8ea636848aca35b9f97c5b5dee30225cf2dd0fe6) | BPF_MAP_TYPE_INODE_STORAGE
task storage                    | 5.11 | [`4cf1bc1f1045`](https://github.com/torvalds/linux/commit/4cf1bc1f10452065a29d576fc5693fc4fab5b919) | BPF_MAP_TYPE_TASK_STORAGE
Bloom filter                    | 5.16 | [`9330986c0300`](https://github.com/torvalds/linux/commit/9330986c03006ab1d33d243b7cfe598a7a3c1baa) | BPF_MAP_TYPE_BLOOM_FILTER
user ringbuf                    | 6.1  | [`583c1f420173`](https://github.com/torvalds/linux/commit/583c1f420173f7d84413a1a1fbf5109d798b4faa) | BPF_MAP_TYPE_USER_RINGBUF

### Map userspace API

Some (but not all) of these *API features* translate to a subcommand beginning with `BPF_MAP_`.
The list of subcommands supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep -W 'bpf_cmd {' include/uapi/linux/bpf.h

Feature | Kernel version | Commit
--------|----------------|-------
Basic operations (lookup, update, delete, `GET_NEXT_KEY`) | 3.18 | [`db20fd2b0108`](https://github.com/torvalds/linux/commit/db20fd2b01087bdfbe30bce314a198eefedcc42e)
Pass flags to `UPDATE_ELEM` | 3.19 | [`3274f52073d8`](https://github.com/torvalds/linux/commit/3274f52073d88b62f3c5ace82ae9d48546232e72)
Pre-alloc map memory by default | 4.6 | [`6c9059817432`](https://github.com/torvalds/linux/commit/6c90598174322b8888029e40dd84a4eb01f56afe)
Pass `NULL` to `GET_NEXT_KEY` | 4.12 | [`8fe45924387b`](https://github.com/torvalds/linux/commit/8fe45924387be6b5c1be59a7eb330790c61d5d10)
Creation: select NUMA node | 4.14 | [`96eabe7a40aa`](https://github.com/torvalds/linux/commit/96eabe7a40aa17e613cf3db2c742ee8b1fc764d0)
Restrict access from syscall side | 4.15 | [`6e71b04a8224`](https://github.com/torvalds/linux/commit/6e71b04a82248ccf13a94b85cbc674a9fefe53f5)
Creation: specify map name | 4.15 | [`ad5b177bd73f`](https://github.com/torvalds/linux/commit/ad5b177bd73f5107d97c36f56395c4281fb6f089)
`LOOKUP_AND_DELETE_ELEM` | 4.20 | [`bd513cd08f10`](https://github.com/torvalds/linux/commit/bd513cd08f10cbe28856f99ae951e86e86803861)
Creation: `BPF_F_ZERO_SEED` | 5.0 | [`96b3b6c9091d`](https://github.com/torvalds/linux/commit/96b3b6c9091d23289721350e32c63cc8749686be)
`BPF_F_LOCK` flag for lookup / update | 5.1 | [`96049f3afd50`](https://github.com/torvalds/linux/commit/96049f3afd50fe8db69fa0068cdca822e747b1e4)
Restrict access from BPF side | 5.2 | [`591fe9888d78`](https://github.com/torvalds/linux/commit/591fe9888d7809d9ee5c828020b6c6ae27c37229)
`FREEZE` | 5.2 | [`87df15de441b`](https://github.com/torvalds/linux/commit/87df15de441bd4add7876ef584da8cabdd9a042a)
mmap() support for array maps | 5.5 | [`fc9702273e2e`](https://github.com/torvalds/linux/commit/fc9702273e2edb90400a34b3be76f7b08fa3344b)
`LOOKUP_BATCH` | 5.6 | [`cb4d03ab499d`](https://github.com/torvalds/linux/commit/cb4d03ab499d4c040f4ab6fd4389d2b49f42b5a5)
`UPDATE_BATCH`, `DELETE_BATCH` | 5.6 | [`aa2e93b8e58e`](https://github.com/torvalds/linux/commit/aa2e93b8e58e18442edfb2427446732415bc215e)
`LOOKUP_AND_DELETE_BATCH` | 5.6 | [`057996380a42`](https://github.com/torvalds/linux/commit/057996380a42bb64ccc04383cfa9c0ace4ea11f0)
`LOOKUP_AND_DELETE_ELEM` support for hash maps | 5.14 | [`3e87f192b405`](https://github.com/torvalds/linux/commit/3e87f192b405960c0fe83e0925bd0dadf4f8cf43)

## XDP

An approximate list of drivers or components supporting XDP programs for your
kernel can be retrieved with:

    git grep -l XDP_SETUP_PROG drivers/

Feature / Driver | Kernel version | Commit
-----------------|----------------|-------
XDP core architecture | 4.8 | [`6a773a15a1e8`](https://github.com/torvalds/linux/commit/6a773a15a1e8874e5eccd2f29190c31085912c95)
Action: drop | 4.8 | [`6a773a15a1e8`](https://github.com/torvalds/linux/commit/6a773a15a1e8874e5eccd2f29190c31085912c95)
Action: pass on to stack | 4.8 | [`6a773a15a1e8`](https://github.com/torvalds/linux/commit/6a773a15a1e8874e5eccd2f29190c31085912c95)
Action: direct forwarding (on same port) | 4.8 | [`6ce96ca348a9`](https://github.com/torvalds/linux/commit/6ce96ca348a9e949f8c43f4d3e98db367d93cffd)
Direct packet data write | 4.8 | [`4acf6c0b84c9`](https://github.com/torvalds/linux/commit/4acf6c0b84c91243c705303cd9ff16421914150d)
Mellanox `mlx4` driver | 4.8 | [`47a38e155037`](https://github.com/torvalds/linux/commit/47a38e155037f417c5740e24ccae6482aedf4b68)
Mellanox `mlx5` driver | 4.9 | [`86994156c736`](https://github.com/torvalds/linux/commit/86994156c736978d113e7927455d4eeeb2128b9f)
Netronome `nfp` driver | 4.10 | [`ecd63a0217d5`](https://github.com/torvalds/linux/commit/ecd63a0217d5f1e8a92f7516f5586d1177b95de2)
QLogic (Cavium) `qed*` drivers | 4.10 | [`496e05170958`](https://github.com/torvalds/linux/commit/496e051709588f832d7a6a420f44f8642b308a87)
`virtio_net` driver | 4.10 | [`f600b6905015`](https://github.com/torvalds/linux/commit/f600b690501550b94e83e07295d9c8b9c4c39f4e)
Broadcom `bnxt_en` driver | 4.11 | [`c6d30e8391b8`](https://github.com/torvalds/linux/commit/c6d30e8391b85e00eb544e6cf047ee0160ee9938)
Intel `ixgbe*` drivers | 4.12 | [`924708081629`](https://github.com/torvalds/linux/commit/9247080816297de4e31abb684939c0e53e3a8a67)
Cavium `thunderx` driver | 4.12 | [`05c773f52b96`](https://github.com/torvalds/linux/commit/05c773f52b96ef3fbc7d9bfa21caadc6247ef7a8)
Generic XDP | 4.12 | [`b5cdae3291f7`](https://github.com/torvalds/linux/commit/b5cdae3291f7be7a34e75affe4c0ec1f7f328b64)
Intel `i40e` driver | 4.13 | [`0c8493d90b6b`](https://github.com/torvalds/linux/commit/0c8493d90b6bb0f5c4fe9217db8f7203f24c0f28)
Action: redirect | 4.14 | [`6453073987ba`](https://github.com/torvalds/linux/commit/6453073987ba392510ab6c8b657844a9312c67f7)
Support for tap | 4.14 | [`761876c857cb`](https://github.com/torvalds/linux/commit/761876c857cb2ef8489fbee01907151da902af91)
Support for veth | 4.14 | [`d445516966dc`](https://github.com/torvalds/linux/commit/d445516966dcb2924741b13b27738b54df2af01a)
Intel `ixgbevf` driver | 4.17 | [`c7aec59657b6`](https://github.com/torvalds/linux/commit/c7aec59657b60f3a29fc7d3274ebefd698879301)
Freescale `dpaa2` driver | 5.0 | [`7e273a8ebdd3`](https://github.com/torvalds/linux/commit/7e273a8ebdd3b83f94eb8b49fc8ee61464f47cc2)
Socionext `netsec` driver | 5.3 | [`ba2b232108d3`](https://github.com/torvalds/linux/commit/ba2b232108d3c2951bab02930a00f23b0cffd5af)
TI `cpsw` driver | 5.3 | [`9ed4050c0d75`](https://github.com/torvalds/linux/commit/9ed4050c0d75768066a07cf66eef4f8dc9d79b52)
Intel `ice` driver |5.5| [`efc2214b6047`](https://github.com/torvalds/linux/commit/efc2214b6047b6f5b4ca53151eba62521b9452d6)
Solarflare `sfc` driver | 5.5 | [`eb9a36be7f3e`](https://github.com/torvalds/linux/commit/eb9a36be7f3ec414700af9a616f035eda1f1e63e)
Marvell `mvneta` driver | 5.5 | [`0db51da7a8e9`](https://github.com/torvalds/linux/commit/0db51da7a8e99f0803ec3a8e25c1a66234a219cb)
Microsoft `hv_netvsc` driver | 5.6 | [`351e1581395f`](https://github.com/torvalds/linux/commit/351e1581395fcc7fb952bbd7dda01238f69968fd)
Amazon `ena` driver | 5.6 | [`838c93dc5449`](https://github.com/torvalds/linux/commit/838c93dc5449e5d6378bae117b0a65a122cf7361)
`xen-netfront` driver | 5.9 | [`6c5aa6fc4def`](https://github.com/torvalds/linux/commit/6c5aa6fc4defc2a0977a2c59e4710d50fa1e834c)
Intel `igb` driver | 5.10 | [`9cbc948b5a20`](https://github.com/torvalds/linux/commit/9cbc948b5a20c9c054d9631099c0426c16da546b)

## Helpers

The list of helpers supported in your kernel can be found in file
[`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h):

    git grep '	FN(' include/uapi/linux/bpf.h

Alphabetical order

Helper | Kernel version | License | Commit |
-------|----------------|---------|--------|
`BPF_FUNC_bind()` | 4.17 |  | [`d74bad4e74ee`](https://github.com/torvalds/linux/commit/d74bad4e74ee373787a9ae24197c17b7cdc428d5) |
`BPF_FUNC_bprm_opts_set()` | 5.11 |  | [`3f6719c7b62f`](https://github.com/torvalds/linux/commit/3f6719c7b62f0327c9091e26d0da10e65668229e)
`BPF_FUNC_btf_find_by_name_kind()` | 5.14 |  | [`3d78417b60fb`](https://github.com/torvalds/linux/commit/3d78417b60fba249cc555468cb72d96f5cde2964)
`BPF_FUNC_cgrp_storage_delete()` | 6.2 | | [`c4bcfb38a95e`](https://github.com/torvalds/linux/commit/c4bcfb38a95edb1021a53f2d0356a78120ecfbe4)
`BPF_FUNC_cgrp_storage_get()` | 6.2 | | [`c4bcfb38a95e`](https://github.com/torvalds/linux/commit/c4bcfb38a95edb1021a53f2d0356a78120ecfbe4)
`BPF_FUNC_check_mtu()` | 5.12 |  | [`34b2021cc616`](https://github.com/torvalds/linux/commit/34b2021cc61642d61c3cf943d9e71925b827941b)
`BPF_FUNC_clone_redirect()` | 4.2 |  | [`3896d655f4d4`](https://github.com/torvalds/linux/commit/3896d655f4d491c67d669a15f275a39f713410f8)
`BPF_FUNC_copy_from_user()` | 5.10 |  | [`07be4c4a3e7a`](https://github.com/torvalds/linux/commit/07be4c4a3e7a0db148e44b16c5190e753d1c8569)
`BPF_FUNC_copy_from_user_task()` | 5.18 | GPL | [`376040e47334`](https://github.com/torvalds/linux/commit/376040e47334c6dc6a939a32197acceb00fe4acf)
`BPF_FUNC_csum_diff()` | 4.6 |  | [`7d672345ed29`](https://github.com/torvalds/linux/commit/7d672345ed295b1356a5d9f7111da1d1d7d65867)
`BPF_FUNC_csum_level()` | 5.7 |  | [`7cdec54f9713`](https://github.com/torvalds/linux/commit/7cdec54f9713256bb170873a1fc5c75c9127c9d2)
`BPF_FUNC_csum_update()` | 4.9 |  | [`36bbef52c7eb`](https://github.com/torvalds/linux/commit/36bbef52c7eb646ed6247055a2acd3851e317857)
`BPF_FUNC_current_task_under_cgroup()` | 4.9 |  | [`60d20f9195b2`](https://github.com/torvalds/linux/commit/60d20f9195b260bdf0ac10c275ae9f6016f9c069)
`BPF_FUNC_d_path()` | 5.10 |  | [`6e22ab9da793`](https://github.com/torvalds/linux/commit/6e22ab9da79343532cd3cde39df25e5a5478c692)
`BPF_FUNC_dynptr_data()` | 5.19 |  | [`34d4ef5775f7`](https://github.com/torvalds/linux/commit/34d4ef5775f776ec4b0d53a02d588bf3195cada6)
`BPF_FUNC_dynptr_from_mem()` | 5.19 |  | [`263ae152e962`](https://github.com/torvalds/linux/commit/263ae152e96253f40c2c276faad8629e096b3bad)
`BPF_FUNC_dynptr_read()` | 5.19 |  | [`13bbbfbea759`](https://github.com/torvalds/linux/commit/13bbbfbea7598ea9f8d9c3d73bf053bb57f9c4b2)
`BPF_FUNC_dynptr_write()` | 5.19 |  | [`13bbbfbea759`](https://github.com/torvalds/linux/commit/13bbbfbea7598ea9f8d9c3d73bf053bb57f9c4b2)
`BPF_FUNC_fib_lookup()` | 4.18 | GPL | [`87f5fc7e48dd`](https://github.com/torvalds/linux/commit/87f5fc7e48dd3175b30dd03b41564e1a8e136323)
`BPF_FUNC_find_vma()` | 5.17 | | [`7c7e3d31e785`](https://github.com/torvalds/linux/commit/7c7e3d31e7856a8260a254f8c71db416f7f9f5a1)
`BPF_FUNC_for_each_map_elem()` | 5.13 | | [`69c087ba6225`](https://github.com/torvalds/linux/commit/69c087ba6225b574afb6e505b72cb75242a3d844)
`BPF_FUNC_get_attach_cookie()` | 5.15 |  | [`7adfc6c9b315`](https://github.com/torvalds/linux/commit/7adfc6c9b315e174cf8743b21b7b691c8766791b)
`BPF_FUNC_get_branch_snapshot()` | 5.16 | GPL | [`856c02dbce4f`](https://github.com/torvalds/linux/commit/856c02dbce4f8d6a5644083db22c11750aa11481)
`BPF_FUNC_get_current_ancestor_cgroup_id()` | 5.6 |  | [`b4490c5c4e02`](https://github.com/torvalds/linux/commit/b4490c5c4e023f09b7d27c9a9d3e7ad7d09ea6bf)
`BPF_FUNC_get_cgroup_classid()` | 4.3 |  | [`8d20aabe1c76`](https://github.com/torvalds/linux/commit/8d20aabe1c76cccac544d9fcc3ad7823d9e98a2d)
`BPF_FUNC_get_current_cgroup_id()` | 4.18 |  | [`bf6fa2c893c5`](https://github.com/torvalds/linux/commit/bf6fa2c893c5237b48569a13fa3c673041430b6c)
`BPF_FUNC_get_current_comm()` | 4.2 |  | [`ffeedafbf023`](https://github.com/torvalds/linux/commit/ffeedafbf0236f03aeb2e8db273b3e5ae5f5bc89)
`BPF_FUNC_get_current_pid_tgid()` | 4.2 |  | [`ffeedafbf023`](https://github.com/torvalds/linux/commit/ffeedafbf0236f03aeb2e8db273b3e5ae5f5bc89)
`BPF_FUNC_get_current_task()` | 4.8 | GPL | [`606274c5abd8`](https://github.com/torvalds/linux/commit/606274c5abd8e245add01bc7145a8cbb92b69ba8)
`BPF_FUNC_get_current_task_btf()` | 5.11 | GPL | [`3ca1032ab7ab`](https://github.com/torvalds/linux/commit/3ca1032ab7ab010eccb107aa515598788f7d93bb)
`BPF_FUNC_get_current_uid_gid()` | 4.2 |  | [`ffeedafbf023`](https://github.com/torvalds/linux/commit/ffeedafbf0236f03aeb2e8db273b3e5ae5f5bc89)
`BPF_FUNC_get_func_arg()` | 5.17 |  | [`f92c1e183604`](https://github.com/torvalds/linux/commit/f92c1e183604c20ce00eb889315fdaa8f2d9e509)
`BPF_FUNC_get_func_arg_cnt()` | 5.17 |  | [`f92c1e183604`](https://github.com/torvalds/linux/commit/f92c1e183604c20ce00eb889315fdaa8f2d9e509)
`BPF_FUNC_get_func_ip()` | 5.15 |  | [`5d8b583d04ae`](https://github.com/torvalds/linux/commit/5d8b583d04aedb3bd5f6d227a334c210c7d735f9)
`BPF_FUNC_get_func_ret()` | 5.17 |  | [`f92c1e183604`](https://github.com/torvalds/linux/commit/f92c1e183604c20ce00eb889315fdaa8f2d9e509)
`BPF_FUNC_get_retval()` | 5.18 |  | [`b44123b4a3dc`](https://github.com/torvalds/linux/commit/b44123b4a3dcad4664d3a0f72c011ffd4c9c4d93)
`BPF_FUNC_get_hash_recalc()` | 4.8 |  | [`13c5c240f789`](https://github.com/torvalds/linux/commit/13c5c240f789bbd2bcacb14a23771491485ae61f)
`BPF_FUNC_get_listener_sock()` | 5.1 |  | [`dbafd7ddd623`](https://github.com/torvalds/linux/commit/dbafd7ddd62369b2f3926ab847cbf8fc40e800b7)
`BPF_FUNC_get_local_storage()` | 4.19 |  | [`cd3394317653`](https://github.com/torvalds/linux/commit/cd3394317653837e2eb5c5d0904a8996102af9fc)
`BPF_FUNC_get_netns_cookie()` | 5.7 |  | [`f318903c0bf4`](https://github.com/torvalds/linux/commit/f318903c0bf42448b4c884732df2bbb0ef7a2284)
`BPF_FUNC_get_ns_current_pid_tgid()` | 5.7 |  | [`b4490c5c4e02`](https://github.com/torvalds/linux/commit/b4490c5c4e023f09b7d27c9a9d3e7ad7d09ea6bf)
`BPF_FUNC_get_numa_node_id()` | 4.10 |  | [`2d0e30c30f84`](https://github.com/torvalds/linux/commit/2d0e30c30f84d08dc16f0f2af41f1b8a85f0755e)
`BPF_FUNC_get_prandom_u32()` | 4.1 |  | [`03e69b508b6f`](https://github.com/torvalds/linux/commit/03e69b508b6f7c51743055c9f61d1dfeadf4b635)
`BPF_FUNC_get_route_realm()` | 4.4 |  | [`c46646d0484f`](https://github.com/torvalds/linux/commit/c46646d0484f5d08e2bede9b45034ba5b8b489cc)
`BPF_FUNC_get_smp_processor_id()` | 4.1 |  | [`c04167ce2ca0`](https://github.com/torvalds/linux/commit/c04167ce2ca0ecaeaafef006cb0d65cf01b68e42)
`BPF_FUNC_get_socket_cookie()` | 4.12 |  | [`91b8270f2a4d`](https://github.com/torvalds/linux/commit/91b8270f2a4d1d9b268de90451cdca63a70052d6)
`BPF_FUNC_get_socket_uid()` | 4.12 |  | [`6acc5c291068`](https://github.com/torvalds/linux/commit/6acc5c2910689fc6ee181bf63085c5efff6a42bd)
`BPF_FUNC_get_stack()` | 4.18 | GPL | [`de2ff05f48af`](https://github.com/torvalds/linux/commit/de2ff05f48afcde816ff4edb217417f62f624ab5)
`BPF_FUNC_get_stackid()` | 4.6 | GPL | [`d5a3b1f69186`](https://github.com/torvalds/linux/commit/d5a3b1f691865be576c2bffa708549b8cdccda19)
`BPF_FUNC_get_task_stack()` | 5.9 | | [`fa28dcb82a38`](https://github.com/torvalds/linux/commit/fa28dcb82a38f8e3993b0fae9106b1a80b59e4f0)
`BPF_FUNC_getsockopt()` | 4.15 |  | [`cd86d1fd2102`](https://github.com/torvalds/linux/commit/cd86d1fd21025fdd6daf23d1288da405e7ad0ec6)
`BPF_FUNC_ima_file_hash()` | 5.18 |  | [`174b16946e39`](https://github.com/torvalds/linux/commit/174b16946e39ebd369097e0f773536c91a8c1a4c)
`BPF_FUNC_ima_inode_hash()` | 5.11 |  | [`27672f0d280a`](https://github.com/torvalds/linux/commit/27672f0d280a3f286a410a8db2004f46ace72a17)
`BPF_FUNC_inode_storage_delete()` | 5.10 |  | [`8ea636848aca`](https://github.com/torvalds/linux/commit/8ea636848aca35b9f97c5b5dee30225cf2dd0fe6)
`BPF_FUNC_inode_storage_get()` | 5.10 |  | [`8ea636848aca`](https://github.com/torvalds/linux/commit/8ea636848aca35b9f97c5b5dee30225cf2dd0fe6)
`BPF_FUNC_jiffies64()` | 5.5 |  | [`5576b991e9c1`](https://github.com/torvalds/linux/commit/5576b991e9c1a11d2cc21c4b94fc75ec27603896)
`BPF_FUNC_kallsyms_lookup_name()` | 5.16 | | [`d6aef08a872b`](https://github.com/torvalds/linux/commit/d6aef08a872b9e23eecc92d0e92393473b13c497)
`BPF_FUNC_kptr_xchg()` | 5.19 | | [`c0a5a21c25f3`](https://github.com/torvalds/linux/commit/c0a5a21c25f37c9fd7b36072f9968cdff1e4aa13)
`BPF_FUNC_ktime_get_boot_ns()` | 5.8 | | [`71d19214776e`](https://github.com/torvalds/linux/commit/71d19214776e61b33da48f7c1b46e522c7f78221)
`BPF_FUNC_ktime_get_coarse_ns()` | 5.11 | | [`d05512618056`](https://github.com/torvalds/linux/commit/d055126180564a57fe533728a4e93d0cb53d49b3)
`BPF_FUNC_ktime_get_ns()` | 4.1 | | [`d9847d310ab4`](https://github.com/torvalds/linux/commit/d9847d310ab4003725e6ed1822682e24bd406908)
`BPF_FUNC_ktime_get_tai_ns()` | 6.1 |  | [`c8996c98f703`](https://github.com/torvalds/linux/commit/c8996c98f703b09afe77a1d247dae691c9849dc1)
`BPF_FUNC_l3_csum_replace()` | 4.1 |  | [`91bc4822c3d6`](https://github.com/torvalds/linux/commit/91bc4822c3d61b9bb7ef66d3b77948a4f9177954)
`BPF_FUNC_l4_csum_replace()` | 4.1 |  | [`91bc4822c3d6`](https://github.com/torvalds/linux/commit/91bc4822c3d61b9bb7ef66d3b77948a4f9177954)
`BPF_FUNC_load_hdr_opt()` | 5.10 |  | [`0813a841566f`](https://github.com/torvalds/linux/commit/0813a841566f0962a5551be7749b43c45f0022a0)
`BPF_FUNC_loop()` | 5.17 |  | [`e6f2dd0f8067`](https://github.com/torvalds/linux/commit/e6f2dd0f80674e9d5960337b3e9c2a242441b326)
`BPF_FUNC_lwt_push_encap()` | 4.18 |  | [`fe94cc290f53`](https://github.com/torvalds/linux/commit/fe94cc290f535709d3c5ebd1e472dfd0aec7ee79)
`BPF_FUNC_lwt_seg6_action()` | 4.18 |  | [`fe94cc290f53`](https://github.com/torvalds/linux/commit/fe94cc290f535709d3c5ebd1e472dfd0aec7ee79)
`BPF_FUNC_lwt_seg6_adjust_srh()` | 4.18 |  | [`fe94cc290f53`](https://github.com/torvalds/linux/commit/fe94cc290f535709d3c5ebd1e472dfd0aec7ee79)
`BPF_FUNC_lwt_seg6_store_bytes()` | 4.18 |  | [`fe94cc290f53`](https://github.com/torvalds/linux/commit/fe94cc290f535709d3c5ebd1e472dfd0aec7ee79)
`BPF_FUNC_map_delete_elem()` | 3.19 |  | [`d0003ec01c66`](https://github.com/torvalds/linux/commit/d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_map_lookup_elem()` | 3.19 |  | [`d0003ec01c66`](https://github.com/torvalds/linux/commit/d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_map_lookup_percpu_elem()` | 5.19 |  | [`07343110b293`](https://github.com/torvalds/linux/commit/07343110b293456d30393e89b86c4dee1ac051c8)
`BPF_FUNC_map_peek_elem()` | 4.20 |  | [`f1a2e44a3aec`](https://github.com/torvalds/linux/commit/f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92)
`BPF_FUNC_map_pop_elem()` | 4.20 |  | [`f1a2e44a3aec`](https://github.com/torvalds/linux/commit/f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92)
`BPF_FUNC_map_push_elem()` | 4.20 |  | [`f1a2e44a3aec`](https://github.com/torvalds/linux/commit/f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92)
`BPF_FUNC_map_update_elem()` | 3.19 |  | [`d0003ec01c66`](https://github.com/torvalds/linux/commit/d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_msg_apply_bytes()` | 4.17 |  | [`2a100317c9eb`](https://github.com/torvalds/linux/commit/2a100317c9ebc204a166f16294884fbf9da074ce)
`BPF_FUNC_msg_cork_bytes()` | 4.17 |  | [`91843d540a13`](https://github.com/torvalds/linux/commit/91843d540a139eb8070bcff8aa10089164436deb)
`BPF_FUNC_msg_pop_data()` | 5.0 |  | [`7246d8ed4dcc`](https://github.com/torvalds/linux/commit/7246d8ed4dcce23f7509949a77be15fa9f0e3d28)
`BPF_FUNC_msg_pull_data()` | 4.17 |  | [`015632bb30da`](https://github.com/torvalds/linux/commit/015632bb30daaaee64e1bcac07570860e0bf3092)
`BPF_FUNC_msg_push_data()` | 4.20 |  | [`6fff607e2f14`](https://github.com/torvalds/linux/commit/6fff607e2f14bd7c63c06c464a6f93b8efbabe28)
`BPF_FUNC_msg_redirect_hash()` | 4.18 |  | [`81110384441a`](https://github.com/torvalds/linux/commit/81110384441a59cff47430f20f049e69b98c17f4)
`BPF_FUNC_msg_redirect_map()` | 4.17 |  | [`4f738adba30a`](https://github.com/torvalds/linux/commit/4f738adba30a7cfc006f605707e7aee847ffefa0)
`BPF_FUNC_per_cpu_ptr()` | 5.10 |  | [`eaa6bcb71ef6`](https://github.com/torvalds/linux/commit/eaa6bcb71ef6ed3dc18fc525ee7e293b06b4882b) |
`BPF_FUNC_perf_event_output()` | 4.4 | GPL | [`a43eec304259`](https://github.com/torvalds/linux/commit/a43eec304259a6c637f4014a6d4767159b6a3aa3)
`BPF_FUNC_perf_event_read()` | 4.3 | GPL | [`35578d798400`](https://github.com/torvalds/linux/commit/35578d7984003097af2b1e34502bc943d40c1804)
`BPF_FUNC_perf_event_read_value()` | 4.15 | GPL | [`908432ca84fc`](https://github.com/torvalds/linux/commit/908432ca84fc229e906ba164219e9ad0fe56f755)
`BPF_FUNC_perf_prog_read_value()` | 4.15 | GPL | [`4bebdc7a85aa`](https://github.com/torvalds/linux/commit/4bebdc7a85aa400c0222b5329861e4ad9252f1e5)
`BPF_FUNC_probe_read()` | 4.1 | GPL | [`2541517c32be`](https://github.com/torvalds/linux/commit/2541517c32be2531e0da59dfd7efc1ce844644f5)
`BPF_FUNC_probe_read_kernel()` | 5.5 | GPL | [`6ae08ae3dea2`](https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47)
`BPF_FUNC_probe_read_kernel_str()` | 5.5 | GPL | [`6ae08ae3dea2`](https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47)
`BPF_FUNC_probe_read_user()` | 5.5 | GPL | [`6ae08ae3dea2`](https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47)
`BPF_FUNC_probe_read_user_str()` | 5.5 | GPL | [`6ae08ae3dea2`](https://github.com/torvalds/linux/commit/6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47)
`BPF_FUNC_probe_read_str()` | 4.11 | GPL | [`a5e8c07059d0`](https://github.com/torvalds/linux/commit/a5e8c07059d0f0b31737408711d44794928ac218)
`BPF_FUNC_probe_write_user()` | 4.8 | GPL | [`96ae52279594`](https://github.com/torvalds/linux/commit/96ae52279594470622ff0585621a13e96b700600)
`BPF_FUNC_rc_keydown()` | 4.18 | GPL | [`f4364dcfc86d`](https://github.com/torvalds/linux/commit/f4364dcfc86df7c1ca47b256eaf6b6d0cdd0d936)
`BPF_FUNC_rc_pointer_rel()` | 5.0 | GPL | [`01d3240a04f4`](https://github.com/torvalds/linux/commit/01d3240a04f4c09392e13c77b54d4423ebce2d72)
`BPF_FUNC_rc_repeat()` | 4.18 | GPL | [`f4364dcfc86d`](https://github.com/torvalds/linux/commit/f4364dcfc86df7c1ca47b256eaf6b6d0cdd0d936)
`BPF_FUNC_read_branch_records()` | 5.6 | GPL | [`fff7b64355ea`](https://github.com/torvalds/linux/commit/fff7b64355eac6e29b50229ad1512315bc04b44e)
`BPF_FUNC_redirect()` | 4.4 |  | [`27b29f63058d`](https://github.com/torvalds/linux/commit/27b29f63058d26c6c1742f1993338280d5a41dc6)
`BPF_FUNC_redirect_map()` | 4.14 |  | [`97f91a7cf04f`](https://github.com/torvalds/linux/commit/97f91a7cf04ff605845c20948b8a80e54cbd3376)
`BPF_FUNC_redirect_neigh()` | 5.10 |  | [`b4ab31414970`](https://github.com/torvalds/linux/commit/b4ab31414970a7a03a5d55d75083f2c101a30592)
`BPF_FUNC_redirect_peer()` | 5.10 |  | [`9aa1206e8f48`](https://github.com/torvalds/linux/commit/9aa1206e8f48222f35a0c809f33b2f4aaa1e2661)
`BPF_FUNC_reserve_hdr_opt()` | 5.10 |  | [`0813a841566f`](https://github.com/torvalds/linux/commit/0813a841566f0962a5551be7749b43c45f0022a0)
`BPF_FUNC_ringbuf_discard()` | 5.8 |  | [`457f44363a88`](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab)
`BPF_FUNC_ringbuf_discard_dynptr()` | 5.19 |  | [`bc34dee65a65`](https://github.com/torvalds/linux/commit/bc34dee65a65e9c920c420005b8a43f2a721a458)
`BPF_FUNC_ringbuf_output()` | 5.8 |  | [`457f44363a88`](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab)
`BPF_FUNC_ringbuf_query()` | 5.8 |  | [`457f44363a88`](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab)
`BPF_FUNC_ringbuf_reserve()` | 5.8 |  | [`457f44363a88`](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab)
`BPF_FUNC_ringbuf_reserve_dynptr()` | 5.19 |  | [`bc34dee65a65`](https://github.com/torvalds/linux/commit/bc34dee65a65e9c920c420005b8a43f2a721a458)
`BPF_FUNC_ringbuf_submit()` | 5.8 |  | [`457f44363a88`](https://github.com/torvalds/linux/commit/457f44363a8894135c85b7a9afd2bd8196db24ab)
`BPF_FUNC_ringbuf_submit_dynptr()` | 5.19 |  | [`bc34dee65a65`](https://github.com/torvalds/linux/commit/bc34dee65a65e9c920c420005b8a43f2a721a458)
`BPF_FUNC_send_signal()` | 5.3 |  | [`8b401f9ed244`](https://github.com/torvalds/linux/commit/8b401f9ed2441ad9e219953927a842d24ed051fc)
`BPF_FUNC_send_signal_thread()` | 5.5 |  | [`8482941f0906`](https://github.com/torvalds/linux/commit/8482941f09067da42f9c3362e15bfb3f3c19d610)
`BPF_FUNC_seq_printf()` | 5.7 | GPL | [`492e639f0c22`](https://github.com/torvalds/linux/commit/492e639f0c222784e2e0f121966375f641c61b15)
`BPF_FUNC_seq_printf_btf()` | 5.10 | | [`eb411377aed9`](https://github.com/torvalds/linux/commit/eb411377aed9e27835e77ee0710ee8f4649958f3)
`BPF_FUNC_seq_write()` | 5.7 | GPL | [`492e639f0c22`](https://github.com/torvalds/linux/commit/492e639f0c222784e2e0f121966375f641c61b15)
`BPF_FUNC_set_hash()` | 4.13 |  | [`ded092cd73c2`](https://github.com/torvalds/linux/commit/ded092cd73c2c56a394b936f86897f29b2e131c0)
`BPF_FUNC_set_hash_invalid()` | 4.9 |  | [`7a4b28c6cc9f`](https://github.com/torvalds/linux/commit/7a4b28c6cc9ffac50f791b99cc7e46106436e5d8)
`BPF_FUNC_set_retval()` | 5.18 |  | [`b44123b4a3dc`](https://github.com/torvalds/linux/commit/b44123b4a3dcad4664d3a0f72c011ffd4c9c4d93)
`BPF_FUNC_setsockopt()` | 4.13 |  | [`8c4b4c7e9ff0`](https://github.com/torvalds/linux/commit/8c4b4c7e9ff0447995750d9329949fa082520269)
`BPF_FUNC_sk_ancestor_cgroup_id()` | 5.7 |  | [`f307fa2cb4c9`](https://github.com/torvalds/linux/commit/f307fa2cb4c935f7f1ff0aeb880c7b44fb9a642b)
`BPF_FUNC_sk_assign()` | 5.6 |  | [`cf7fbe660f2d`](https://github.com/torvalds/linux/commit/cf7fbe660f2dbd738ab58aea8e9b0ca6ad232449)
`BPF_FUNC_sk_cgroup_id()` | 5.7 |  | [`f307fa2cb4c9`](https://github.com/torvalds/linux/commit/f307fa2cb4c935f7f1ff0aeb880c7b44fb9a642b)
`BPF_FUNC_sk_fullsock()` | 5.1 |  | [`46f8bc92758c`](https://github.com/torvalds/linux/commit/46f8bc92758c6259bcf945e9216098661c1587cd)
`BPF_FUNC_sk_lookup_tcp()` | 4.20 |  | [`6acc9b432e67`](https://github.com/torvalds/linux/commit/6acc9b432e6714d72d7d77ec7c27f6f8358d0c71)
`BPF_FUNC_sk_lookup_udp()` | 4.20 |  | [`6acc9b432e67`](https://github.com/torvalds/linux/commit/6acc9b432e6714d72d7d77ec7c27f6f8358d0c71)
`BPF_FUNC_sk_redirect_hash()` | 4.18 |  | [`81110384441a`](https://github.com/torvalds/linux/commit/81110384441a59cff47430f20f049e69b98c17f4)
`BPF_FUNC_sk_redirect_map()` | 4.14 |  | [`174a79ff9515`](https://github.com/torvalds/linux/commit/174a79ff9515f400b9a6115643dafd62a635b7e6)
`BPF_FUNC_sk_release()` | 4.20 |  | [`6acc9b432e67`](https://github.com/torvalds/linux/commit/6acc9b432e6714d72d7d77ec7c27f6f8358d0c71)
`BPF_FUNC_sk_select_reuseport()` | 4.19 |  | [`2dbb9b9e6df6`](https://github.com/torvalds/linux/commit/2dbb9b9e6df67d444fbe425c7f6014858d337adf)
`BPF_FUNC_sk_storage_delete()` | 5.2 |  | [`6ac99e8f23d4`](https://github.com/torvalds/linux/commit/6ac99e8f23d4b10258406ca0dd7bffca5f31da9d)
`BPF_FUNC_sk_storage_get()` | 5.2 |  | [`6ac99e8f23d4`](https://github.com/torvalds/linux/commit/6ac99e8f23d4b10258406ca0dd7bffca5f31da9d)
`BPF_FUNC_skb_adjust_room()` | 4.13 |  | [`2be7e212d541`](https://github.com/torvalds/linux/commit/2be7e212d5419a400d051c84ca9fdd083e5aacac)
`BPF_FUNC_skb_ancestor_cgroup_id()` | 4.19 |  | [`7723628101aa`](https://github.com/torvalds/linux/commit/7723628101aaeb1d723786747529b4ea65c5b5c5)
`BPF_FUNC_skb_change_head()` | 4.10 |  | [`3a0af8fd61f9`](https://github.com/torvalds/linux/commit/3a0af8fd61f90920f6fa04e4f1e9a6a73c1b4fd2)
`BPF_FUNC_skb_change_proto()` | 4.8 |  | [`6578171a7ff0`](https://github.com/torvalds/linux/commit/6578171a7ff0c31dc73258f93da7407510abf085)
`BPF_FUNC_skb_change_tail()` | 4.9 |  | [`5293efe62df8`](https://github.com/torvalds/linux/commit/5293efe62df81908f2e90c9820c7edcc8e61f5e9)
`BPF_FUNC_skb_change_type()` | 4.8 |  | [`d2485c4242a8`](https://github.com/torvalds/linux/commit/d2485c4242a826fdf493fd3a27b8b792965b9b9e)
`BPF_FUNC_skb_cgroup_classid()` | 5.10 |  | [`b426ce83baa7`](https://github.com/torvalds/linux/commit/b426ce83baa7dff947fb354118d3133f2953aac8)
`BPF_FUNC_skb_cgroup_id()` | 4.18 |  | [`cb20b08ead40`](https://github.com/torvalds/linux/commit/cb20b08ead401fd17627a36f035c0bf5bfee5567)
`BPF_FUNC_skb_ecn_set_ce()` | 5.1 |  | [`f7c917ba11a6`](https://github.com/torvalds/linux/commit/f7c917ba11a67632a8452ea99fe132f626a7a2cc)
`BPF_FUNC_skb_get_tunnel_key()` | 4.3 |  | [`d3aa45ce6b94`](https://github.com/torvalds/linux/commit/d3aa45ce6b94c65b83971257317867db13e5f492)
`BPF_FUNC_skb_get_tunnel_opt()` | 4.6 |  | [`14ca0751c96f`](https://github.com/torvalds/linux/commit/14ca0751c96f8d3d0f52e8ed3b3236f8b34d3460)
`BPF_FUNC_skb_get_xfrm_state()` | 4.18 |  | [`12bed760a78d`](https://github.com/torvalds/linux/commit/12bed760a78da6e12ac8252fec64d019a9eac523)
`BPF_FUNC_skb_load_bytes()` | 4.5 |  | [`05c74e5e53f6`](https://github.com/torvalds/linux/commit/05c74e5e53f6cb07502c3e6a820f33e2777b6605)
`BPF_FUNC_skb_load_bytes_relative()` | 4.18 |  | [`4e1ec56cdc59`](https://github.com/torvalds/linux/commit/4e1ec56cdc59746943b2acfab3c171b930187bbe)
`BPF_FUNC_skb_output()` | 5.5 |  | [`a7658e1a4164`](https://github.com/torvalds/linux/commit/a7658e1a4164ce2b9eb4a11aadbba38586e93bd6)
`BPF_FUNC_skb_pull_data()` | 4.9 |  | [`36bbef52c7eb`](https://github.com/torvalds/linux/commit/36bbef52c7eb646ed6247055a2acd3851e317857)
`BPF_FUNC_skb_set_tstamp()` | 5.18 |  | [`9bb984f28d5b`](https://github.com/torvalds/linux/commit/9bb984f28d5bcb917d35d930fcfb89f90f9449fd)
`BPF_FUNC_skb_set_tunnel_key()` | 4.3 |  | [`d3aa45ce6b94`](https://github.com/torvalds/linux/commit/d3aa45ce6b94c65b83971257317867db13e5f492)
`BPF_FUNC_skb_set_tunnel_opt()` | 4.6 |  | [`14ca0751c96f`](https://github.com/torvalds/linux/commit/14ca0751c96f8d3d0f52e8ed3b3236f8b34d3460)
`BPF_FUNC_skb_store_bytes()` | 4.1 |  | [`91bc4822c3d6`](https://github.com/torvalds/linux/commit/91bc4822c3d61b9bb7ef66d3b77948a4f9177954)
`BPF_FUNC_skb_under_cgroup()` | 4.8 |  | [`4a482f34afcc`](https://github.com/torvalds/linux/commit/4a482f34afcc162d8456f449b137ec2a95be60d8)
`BPF_FUNC_skb_vlan_pop()` | 4.3 |  | [`4e10df9a60d9`](https://github.com/torvalds/linux/commit/4e10df9a60d96ced321dd2af71da558c6b750078)
`BPF_FUNC_skb_vlan_push()` | 4.3 |  | [`4e10df9a60d9`](https://github.com/torvalds/linux/commit/4e10df9a60d96ced321dd2af71da558c6b750078)
`BPF_FUNC_skc_lookup_tcp()` | 5.2 |  | [`edbf8c01de5a`](https://github.com/torvalds/linux/commit/edbf8c01de5a104a71ed6df2bf6421ceb2836a8e)
`BPF_FUNC_skc_to_mctcp_sock()` | 5.19 |  | [`3bc253c2e652`](https://github.com/torvalds/linux/commit/3bc253c2e652cf5f12cd8c00d80d8ec55d67d1a7)
`BPF_FUNC_skc_to_tcp_sock()` | 5.9 |  | [`478cfbdf5f13`](https://github.com/torvalds/linux/commit/478cfbdf5f13dfe09cfd0b1cbac821f5e27f6108)
`BPF_FUNC_skc_to_tcp_request_sock()` | 5.9 |  | [`478cfbdf5f13`](https://github.com/torvalds/linux/commit/478cfbdf5f13dfe09cfd0b1cbac821f5e27f6108)
`BPF_FUNC_skc_to_tcp_timewait_sock()` | 5.9 |  | [`478cfbdf5f13`](https://github.com/torvalds/linux/commit/478cfbdf5f13dfe09cfd0b1cbac821f5e27f6108)
`BPF_FUNC_skc_to_tcp6_sock()` | 5.9 |  | [`af7ec1383361`](https://github.com/torvalds/linux/commit/af7ec13833619e17f03aa73a785a2f871da6d66b)
`BPF_FUNC_skc_to_udp6_sock()` | 5.9 |  | [`0d4fad3e57df`](https://github.com/torvalds/linux/commit/0d4fad3e57df2bf61e8ffc8d12a34b1caf9b8835)
`BPF_FUNC_skc_to_unix_sock()` | 5.16 |  | [`9eeb3aa33ae0`](https://github.com/torvalds/linux/commit/9eeb3aa33ae005526f672b394c1791578463513f)
`BPF_FUNC_snprintf()` | 5.13 | | [`7b15523a989b`](https://github.com/torvalds/linux/commit/7b15523a989b63927c2bb08e9b5b0bbc10b58bef)
`BPF_FUNC_snprintf_btf()` | 5.10 | | [`c4d0bfb45068`](https://github.com/torvalds/linux/commit/c4d0bfb45068d853a478b9067a95969b1886a30f)
`BPF_FUNC_sock_from_file()` | 5.11 |  | [`4f19cab76136`](https://github.com/torvalds/linux/commit/4f19cab76136e800a3f04d8c9aa4d8e770e3d3d8)
`BPF_FUNC_sock_hash_update()` | 4.18 |  | [`81110384441a`](https://github.com/torvalds/linux/commit/81110384441a59cff47430f20f049e69b98c17f4)
`BPF_FUNC_sock_map_update()` | 4.14 |  | [`174a79ff9515`](https://github.com/torvalds/linux/commit/174a79ff9515f400b9a6115643dafd62a635b7e6)
`BPF_FUNC_spin_lock()` | 5.1 |  | [`d83525ca62cf`](https://github.com/torvalds/linux/commit/d83525ca62cf8ebe3271d14c36fb900c294274a2)
`BPF_FUNC_spin_unlock()` | 5.1 |  | [`d83525ca62cf`](https://github.com/torvalds/linux/commit/d83525ca62cf8ebe3271d14c36fb900c294274a2)
`BPF_FUNC_store_hdr_opt()` | 5.10 |  | [`0813a841566f`](https://github.com/torvalds/linux/commit/0813a841566f0962a5551be7749b43c45f0022a0)
`BPF_FUNC_strncmp()` | 5.17 |  | [`c5fb19937455`](https://github.com/torvalds/linux/commit/c5fb19937455095573a19ddcbff32e993ed10e35)
`BPF_FUNC_strtol()` | 5.2 |  | [`d7a4cb9b6705`](https://github.com/torvalds/linux/commit/d7a4cb9b6705a89937d12c8158a35a3145dc967a)
`BPF_FUNC_strtoul()` | 5.2 |  | [`d7a4cb9b6705`](https://github.com/torvalds/linux/commit/d7a4cb9b6705a89937d12c8158a35a3145dc967a)
`BPF_FUNC_sys_bpf()` | 5.14 |  | [`79a7f8bdb159`](https://github.com/torvalds/linux/commit/79a7f8bdb159d9914b58740f3d31d602a6e4aca8)
`BPF_FUNC_sys_close()` | 5.14 |  | [`3abea089246f`](https://github.com/torvalds/linux/commit/3abea089246f76c1517b054ddb5946f3f1dbd2c0)
`BPF_FUNC_sysctl_get_current_value()` | 5.2 |  | [`1d11b3016cec`](https://github.com/torvalds/linux/commit/1d11b3016cec4ed9770b98e82a61708c8f4926e7)
`BPF_FUNC_sysctl_get_name()` | 5.2 |  | [`808649fb787d`](https://github.com/torvalds/linux/commit/808649fb787d918a48a360a668ee4ee9023f0c11)
`BPF_FUNC_sysctl_get_new_value()` | 5.2 |  | [`4e63acdff864`](https://github.com/torvalds/linux/commit/4e63acdff864654cee0ac5aaeda3913798ee78f6)
`BPF_FUNC_sysctl_set_new_value()` | 5.2 |  | [`4e63acdff864`](https://github.com/torvalds/linux/commit/4e63acdff864654cee0ac5aaeda3913798ee78f6)
`BPF_FUNC_tail_call()` | 4.2 |  | [`04fd61ab36ec`](https://github.com/torvalds/linux/commit/04fd61ab36ec065e194ab5e74ae34a5240d992bb)
`BPF_FUNC_task_pt_regs()` | 5.15 | GPL | [`dd6e10fbd9f`](https://github.com/torvalds/linux/commit/dd6e10fbd9fb86a571d925602c8a24bb4d09a2a7)
`BPF_FUNC_task_storage_delete()` | 5.11 |  | [`4cf1bc1f1045`](https://github.com/torvalds/linux/commit/4cf1bc1f10452065a29d576fc5693fc4fab5b919)
`BPF_FUNC_task_storage_get()` | 5.11 |  | [`4cf1bc1f1045`](https://github.com/torvalds/linux/commit/4cf1bc1f10452065a29d576fc5693fc4fab5b919)
`BPF_FUNC_tcp_check_syncookie()` | 5.2 |  | [`399040847084`](https://github.com/torvalds/linux/commit/399040847084a69f345e0a52fd62f04654e0fce3)
`BPF_FUNC_tcp_gen_syncookie()` | 5.3 |  | [`70d66244317e`](https://github.com/torvalds/linux/commit/70d66244317e958092e9c971b08dd5b7fd29d9cb#diff-05da4bf36c7fbcd176254e1615d98b28)
`BPF_FUNC_tcp_raw_check_syncookie_ipv4()` | 6.0 |  | [`33bf9885040c`](https://github.com/torvalds/linux/commit/33bf9885040c399cf6a95bd33216644126728e14)
`BPF_FUNC_tcp_raw_check_syncookie_ipv6()` | 6.0 |  | [`33bf9885040c`](https://github.com/torvalds/linux/commit/33bf9885040c399cf6a95bd33216644126728e14)
`BPF_FUNC_tcp_raw_gen_syncookie_ipv4()` | 6.0 |  | [`33bf9885040c`](https://github.com/torvalds/linux/commit/33bf9885040c399cf6a95bd33216644126728e14)
`BPF_FUNC_tcp_raw_gen_syncookie_ipv6()` | 6.0 |  | [`33bf9885040c`](https://github.com/torvalds/linux/commit/33bf9885040c399cf6a95bd33216644126728e14)
`BPF_FUNC_tcp_send_ack()` | 5.5 | | [`206057fe020a`](https://github.com/torvalds/linux/commit/206057fe020ac5c037d5e2dd6562a9bd216ec765)
`BPF_FUNC_tcp_sock()` | 5.1 |  | [`655a51e536c0`](https://github.com/torvalds/linux/commit/655a51e536c09d15ffa3603b1b6fce2b45b85a1f)
`BPF_FUNC_this_cpu_ptr()` | 5.10 |  | [`63d9b80dcf2c`](https://github.com/torvalds/linux/commit/63d9b80dcf2c67bc5ade61cbbaa09d7af21f43f1) |
`BPF_FUNC_timer_init()` | 5.15 |  | [`b00628b1c7d5`](https://github.com/torvalds/linux/commit/b00628b1c7d595ae5b544e059c27b1f5828314b4)
`BPF_FUNC_timer_set_callback()` | 5.15 |  | [`b00628b1c7d5`](https://github.com/torvalds/linux/commit/b00628b1c7d595ae5b544e059c27b1f5828314b4)
`BPF_FUNC_timer_start()` | 5.15 |  | [`b00628b1c7d5`](https://github.com/torvalds/linux/commit/b00628b1c7d595ae5b544e059c27b1f5828314b4)
`BPF_FUNC_timer_cancel()` | 5.15 |  | [`b00628b1c7d5`](https://github.com/torvalds/linux/commit/b00628b1c7d595ae5b544e059c27b1f5828314b4)
`BPF_FUNC_trace_printk()` | 4.1 | GPL | [`9c959c863f82`](https://github.com/torvalds/linux/commit/9c959c863f8217a2ff3d7c296e8223654d240569)
`BPF_FUNC_trace_vprintk()` | 5.16 | GPL | [`10aceb629e19`](https://github.com/torvalds/linux/commit/10aceb629e198429c849d5e995c3bb1ba7a9aaa3)
`BPF_FUNC_user_ringbuf_drain()` | 6.1 | | [`205715673844`](https://github.com/torvalds/linux/commit/20571567384428dfc9fe5cf9f2e942e1df13c2dd)
`BPF_FUNC_xdp_adjust_head()` | 4.10 |  | [`17bedab27231`](https://github.com/torvalds/linux/commit/17bedab2723145d17b14084430743549e6943d03)
`BPF_FUNC_xdp_adjust_meta()` | 4.15 |  | [`de8f3a83b0a0`](https://github.com/torvalds/linux/commit/de8f3a83b0a0fddb2cf56e7a718127e9619ea3da)
`BPF_FUNC_xdp_adjust_tail()` | 4.18 |  | [`b32cc5b9a346`](https://github.com/torvalds/linux/commit/b32cc5b9a346319c171e3ad905e0cddda032b5eb)
`BPF_FUNC_xdp_get_buff_len()` | 5.18 |  | [`0165cc817075`](https://github.com/torvalds/linux/commit/0165cc817075cf701e4289838f1d925ff1911b3e)
`BPF_FUNC_xdp_load_bytes()` | 5.18 |  | [`3f364222d032`](https://github.com/torvalds/linux/commit/3f364222d032eea6b245780e845ad213dab28cdd)
`BPF_FUNC_xdp_store_bytes()` | 5.18 |  | [`3f364222d032`](https://github.com/torvalds/linux/commit/3f364222d032eea6b245780e845ad213dab28cdd)
`BPF_FUNC_xdp_output()` | 5.6 | GPL | [`d831ee84bfc9`](https://github.com/torvalds/linux/commit/d831ee84bfc9173eecf30dbbc2553ae81b996c60)
`BPF_FUNC_override_return()` | 4.16 | GPL | [`9802d86585db`](https://github.com/torvalds/linux/commit/9802d86585db91655c7d1929a4f6bbe0952ea88e)
`BPF_FUNC_sock_ops_cb_flags_set()` | 4.16 |  | [`b13d88072172`](https://github.com/torvalds/linux/commit/b13d880721729384757f235166068c315326f4a1)

Note: GPL-only BPF helpers require a GPL-compatible license. The current licenses considered GPL-compatible by the kernel are:

* GPL
* GPL v2
* GPL and additional rights
* Dual BSD/GPL
* Dual MIT/GPL
* Dual MPL/GPL

Check the list of GPL-compatible licenses in your [kernel source code](https://github.com/torvalds/linux/blob/master/include/linux/license.h).

## Program Types
The list of program types and supported helper functions can be retrieved with:

    git grep -W 'func_proto(enum bpf_func_id func_id' kernel/ net/ drivers/

|Program Type| Helper Functions|
|------------|-----------------|
|`BPF_PROG_TYPE_SOCKET_FILTER`|`BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_perf_event_output()` <br> `Base functions`|
|`BPF_PROG_TYPE_KPROBE`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_event_read_value()` <br> `BPF_FUNC_override_return()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_SCHED_CLS` <br> `BPF_PROG_TYPE_SCHED_ACT`|`BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_csum_update()` <br> `BPF_FUNC_l3_csum_replace()` <br> `BPF_FUNC_l4_csum_replace()` <br> `BPF_FUNC_clone_redirect()` <br> `BPF_FUNC_get_cgroup_classid()` <br> `BPF_FUNC_skb_vlan_push()` <br> `BPF_FUNC_skb_vlan_pop()` <br> `BPF_FUNC_skb_change_proto()` <br> `BPF_FUNC_skb_change_type()` <br> `BPF_FUNC_skb_adjust_room()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_get_tunnel_key()` <br> `BPF_FUNC_skb_set_tunnel_key()` <br> `BPF_FUNC_skb_get_tunnel_opt()` <br> `BPF_FUNC_skb_set_tunnel_opt()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_get_route_realm()` <br> `BPF_FUNC_get_hash_recalc()` <br> `BPF_FUNC_set_hash_invalid()` <br> `BPF_FUNC_set_hash()` <br> `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_skb_under_cgroup()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_fib_lookup()` <br> `BPF_FUNC_skb_get_xfrm_state()` <br> `BPF_FUNC_skb_cgroup_id()` <br> `Base functions`|
|`BPF_PROG_TYPE_TRACEPOINT`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_d_path()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_XDP`| `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_xdp_adjust_head()` <br> `BPF_FUNC_xdp_adjust_meta()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_redirect_map()` <br> `BPF_FUNC_xdp_adjust_tail()` <br> `BPF_FUNC_fib_lookup()` <br> `Base functions`|
|`BPF_PROG_TYPE_PERF_EVENT`| `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_perf_prog_read_value()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_CGROUP_SKB`|`BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_load_bytes_relative()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `Base functions`|
|`BPF_PROG_TYPE_CGROUP_SOCK`|`BPF_FUNC_get_current_uid_gid()` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_IN`|`BPF_FUNC_lwt_push_encap()` <br> `LWT functions` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_OUT`| `LWT functions` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_XMIT`| `BPF_FUNC_skb_get_tunnel_key()` <br> `BPF_FUNC_skb_set_tunnel_key()` <br> `BPF_FUNC_skb_get_tunnel_opt()` <br> `BPF_FUNC_skb_set_tunnel_opt()` <br> `BPF_FUNC_redirect()` <br> `BPF_FUNC_clone_redirect()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_change_head()` <br> `BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_csum_update()` <br> `BPF_FUNC_l3_csum_replace()` <br> `BPF_FUNC_l4_csum_replace()` <br> `BPF_FUNC_set_hash_invalid()` <br> `LWT functions`|
|`BPF_PROG_TYPE_SOCK_OPS`|`BPF_FUNC_setsockopt()` <br> `BPF_FUNC_getsockopt()` <br> `BPF_FUNC_sock_ops_cb_flags_set()` <br> `BPF_FUNC_sock_map_update()` <br> `BPF_FUNC_sock_hash_update()` <br> `BPF_FUNC_get_socket_cookie()` <br> `Base functions`|
|`BPF_PROG_TYPE_SK_SKB`|`BPF_FUNC_skb_store_bytes()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_skb_change_tail()` <br> `BPF_FUNC_skb_change_head()` <br> `BPF_FUNC_get_socket_cookie()` <br> `BPF_FUNC_get_socket_uid()` <br> `BPF_FUNC_sk_redirect_map()` <br> `BPF_FUNC_sk_redirect_hash()` <br> `BPF_FUNC_sk_lookup_tcp()` <br> `BPF_FUNC_sk_lookup_udp()` <br> `BPF_FUNC_sk_release()` <br> `Base functions`|
|`BPF_PROG_TYPE_CGROUP_DEVICE`|`BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_trace_printk()`|
|`BPF_PROG_TYPE_SK_MSG`|`BPF_FUNC_msg_redirect_map()` <br> `BPF_FUNC_msg_redirect_hash()` <br> `BPF_FUNC_msg_apply_bytes()` <br> `BPF_FUNC_msg_cork_bytes()` <br> `BPF_FUNC_msg_pull_data()` <br> `BPF_FUNC_msg_push_data()` <br> `BPF_FUNC_msg_pop_data()` <br> `Base functions`|
|`BPF_PROG_TYPE_RAW_TRACEPOINT`|`BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_stackid()` <br> `BPF_FUNC_get_stack()` <br> `BPF_FUNC_skb_output()` <br> `Tracing functions`|
|`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`|`BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_bind()` <br> `BPF_FUNC_get_socket_cookie()` <br> `Base functions`|
|`BPF_PROG_TYPE_LWT_SEG6LOCAL`|`BPF_FUNC_lwt_seg6_store_bytes()` <br> `BPF_FUNC_lwt_seg6_action()` <br> `BPF_FUNC_lwt_seg6_adjust_srh()` <br> `LWT functions`|
|`BPF_PROG_TYPE_LIRC_MODE2`|`BPF_FUNC_rc_repeat()` <br> `BPF_FUNC_rc_keydown()` <br> `BPF_FUNC_rc_pointer_rel()` <br> `BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_trace_printk()`|
|`BPF_PROG_TYPE_SK_REUSEPORT`|`BPF_FUNC_sk_select_reuseport()` <br> `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_load_bytes_relative()` <br> `Base functions`|
|`BPF_PROG_TYPE_FLOW_DISSECTOR`|`BPF_FUNC_skb_load_bytes()` <br> `Base functions`|

|Function Group| Functions|
|------------------|-------|
|`Base functions`| `BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_map_peek_elem()` <br> `BPF_FUNC_map_pop_elem()` <br> `BPF_FUNC_map_push_elem()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_spin_lock()` <br> `BPF_FUNC_spin_unlock()` |
|`Tracing functions`|`BPF_FUNC_map_lookup_elem()` <br> `BPF_FUNC_map_update_elem()` <br> `BPF_FUNC_map_delete_elem()` <br> `BPF_FUNC_probe_read()` <br> `BPF_FUNC_ktime_get_boot_ns()` <br> `BPF_FUNC_ktime_get_ns()` <br> `BPF_FUNC_tail_call()` <br> `BPF_FUNC_get_current_pid_tgid()` <br> `BPF_FUNC_get_current_task()` <br> `BPF_FUNC_get_current_uid_gid()` <br> `BPF_FUNC_get_current_comm()` <br> `BPF_FUNC_trace_printk()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_get_numa_node_id()` <br> `BPF_FUNC_perf_event_read()` <br> `BPF_FUNC_probe_write_user()` <br> `BPF_FUNC_current_task_under_cgroup()` <br> `BPF_FUNC_get_prandom_u32()` <br> `BPF_FUNC_probe_read_str()` <br> `BPF_FUNC_get_current_cgroup_id()` <br> `BPF_FUNC_send_signal()` <br> `BPF_FUNC_probe_read_kernel()` <br> `BPF_FUNC_probe_read_kernel_str()` <br> `BPF_FUNC_probe_read_user()` <br> `BPF_FUNC_probe_read_user_str()` <br> `BPF_FUNC_send_signal_thread()` <br> `BPF_FUNC_get_ns_current_pid_tgid()` <br> `BPF_FUNC_xdp_output()` <br> `BPF_FUNC_get_task_stack()`|
|`LWT functions`|  `BPF_FUNC_skb_load_bytes()` <br> `BPF_FUNC_skb_pull_data()` <br> `BPF_FUNC_csum_diff()` <br> `BPF_FUNC_get_cgroup_classid()` <br> `BPF_FUNC_get_route_realm()` <br> `BPF_FUNC_get_hash_recalc()` <br> `BPF_FUNC_perf_event_output()` <br> `BPF_FUNC_get_smp_processor_id()` <br> `BPF_FUNC_skb_under_cgroup()`|
