# BPF Features by Linux Kernel Version

## eBPF support

Kernel version | Commit
---------------|-------
3.15 | [bd4cf0ed331a](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)

## JIT compiling

Feature / Architecture | Kernel version | Commit
-----------------------|----------------|-------
x86\_64 | 3.16 | [622582786c9e](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=622582786c9e041d0bd52bde201787adeab249f8)
ARM64 | 3.18 | [e54bcde3d69d](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=e54bcde3d69d40023ae77727213d14f920eb264a)
s390 | 4.1 | [054623105728](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=054623105728b06852f077299e2bf1bf3d5f2b0b)
Constant blinding for JIT machines | 4.7 | [4f3446bb809f](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4f3446bb809f20ad56cadf712e6006815ae7a8f9)
PowerPC64 | 4.8 | [156d0e290e96](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=156d0e290e969caba25f1851c52417c14d141b24)
Constant blinding - PowerPC64 | 4.9 | [b7b7013cac55](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b7b7013cac55d794940bd9cb7b7c55c9dececac4)
Sparc64 | 4.12 | [7a12b5031c6b](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=7a12b5031c6b947cc13918237ae652b536243b76)
MIPS | 4.13 | [f381bf6d82f0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=f381bf6d82f032b7410185b35d000ea370ac706b)
ARM32 | 4.14 | [39c13c204bb1](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=39c13c204bb1150d401e27d41a9d8b332be47c49)

## Main features

Feature | Kernel version | Commit
--------|----------------|-------
`AF_PACKET` (libpcap/tcpdump, `cls_bpf` classifier, netfilter's `xt_bpf`, team driver's load-balancing mode…) | 3.15 | [bd4cf0ed331a](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)
Kernel helpers | 3.15 | [bd4cf0ed331a](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=bd4cf0ed331a275e9bf5a49e6d0fd55dffc551b8)
`bpf()` syscall | 3.18 | [99c55f7d47c0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=99c55f7d47c0dc6fc64729f37bf435abf43f4c60)
Tables (_a.k.a._ Maps; details below) | 3.18 | [99c55f7d47c0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=99c55f7d47c0dc6fc64729f37bf435abf43f4c60)
BPF attached to sockets | 3.19 | [89aa075832b0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=89aa075832b0da4402acebd698d0411dcc82d03e)
BPF attached to `kprobes` | 4.1 | [2541517c32be](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=2541517c32be2531e0da59dfd7efc1ce844644f5)
`cls_bpf` / `act_bpf` for `tc` | 4.1 | [e2e9b6541dd4](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=e2e9b6541dd4b31848079da80fe2253daaafb549)
Tail calls | 4.2 | [04fd61ab36ec](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=04fd61ab36ec065e194ab5e74ae34a5240d992bb)
Non-root programs on sockets | 4.4 | [1be7f75d1668](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1be7f75d1668d6296b80bf35dcf6762393530afc)
Persistent maps and programs (virtual FS) | 4.4 | [b2197755b263](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b2197755b2633e164a439682fb05a9b5ea48f706)
`tc`'s `direct-action` (`da`) mode | 4.4 | [045efa82ff56](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=045efa82ff563cd4e656ca1c2e354fa5bf6bbda4)
`tc`'s `clsact` qdisc | 4.5 | [1f211a1b929c](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1f211a1b929c804100e138c5d3d656992cfd5622)
BPF attached to tracepoints | 4.7 | [98b5c2c65c29](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=98b5c2c65c2951772a8fc661f50d675e450e8bce)
Direct packet access | 4.7 | [969bf05eb3ce](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=969bf05eb3cedd5a8d4b7c346a85c2ede87a6d6d)
XDP (see below) | 4.8 | [6a773a15a1e8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6a773a15a1e8874e5eccd2f29190c31085912c95)
BPF attached to perf events | 4.9 | [0515e5999a46](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=0515e5999a466dfe6e1924f460da599bb6821487)
Hardware offload for `tc`'s `cls_bpf` | 4.9 | [332ae8e2f6ec](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=332ae8e2f6ecda5e50c5c62ed62894963e3a83f5)
Verifier exposure and internal hooks | 4.9 | [13a27dfc6697](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=13a27dfc669724564aafa2699976ee756029fed2)
BPF attached to cgroups for socket filtering | 4.10 | [0e33661de493](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=0e33661de493db325435d565a4a722120ae4cbf3)
Lightweight tunnel encapsulation | 4.10 | [3a0af8fd61f9](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=3a0af8fd61f90920f6fa04e4f1e9a6a73c1b4fd2)
**e**BPF support for `xt_bpf` module (iptables) | 4.10 | [2c16d6033264](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=2c16d60332643e90d4fa244f4a706c454b8c7569)
BPF program tag | 4.10 | [7bd509e311f4](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=7bd509e311f408f7a5132fcdde2069af65fa05ae)
Tracepoints to debug BPF | 4.11 | [a67edbf4fb6d](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=a67edbf4fb6deadcfe57a04a134abed4a5ba3bb5)
Testing / benchmarking BPF programs | 4.12 | [1cf1cae963c2](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1cf1cae963c2e6032aebe1637e995bc2f5d330f4)
BPF programs and maps IDs | 4.13 | [dc4bb0e23561](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=dc4bb0e2356149aee4cdae061936f3bbdd45595c)
BPF support for `sock_ops` | 4.13 | [40304b2a1567](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=40304b2a1567fecc321f640ee4239556dd0f3ee0)
BPF support for skbs on sockets | 4.14 | [b005fd189cec](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=b005fd189cec9407b700599e1e80e0552446ee79)

## Tables (_a.k.a._ Maps)

Table type | Kernel version | Commit
-----------|----------------|-------
Hash | 3.19 | [0f8e4bd8a1fc](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=0f8e4bd8a1fc8c4185f1630061d0a1f2d197a475)
Array | 3.19 | [28fbcfa08d8e](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=28fbcfa08d8ed7c5a50d41a0433aad222835e8e3)
Tail call (`PROG_ARRAY`) | 4.2 | [04fd61ab36ec](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=04fd61ab36ec065e194ab5e74ae34a5240d992bb)
Perf events | 4.3 | [ea317b267e9d](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ea317b267e9d03a8241893aa176fba7661d07579)
Per-CPU hash | 4.6 | [824bd0ce6c7c](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=824bd0ce6c7c43a9e1e210abf124958e54d88342)
Per-CPU array | 4.6 | [a10423b87a7e](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=a10423b87a7eae75da79ce80a8d9475047a674ee)
Stack trace | 4.6 | [d5a3b1f69186](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d5a3b1f691865be576c2bffa708549b8cdccda19)
Pre-alloc maps memory | 4.6 | [6c9059817432](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6c90598174322b8888029e40dd84a4eb01f56afe)
cgroup array | 4.8 | [4ed8ec521ed5](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4ed8ec521ed57c4e207ad464ca0388776de74d4b)
LRU hash | 4.10 | [29ba732acbee](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=29ba732acbeece1e34c68483d1ec1f3720fa1bb3) [3a08c2fd7634](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=3a08c2fd763450a927d1130de078d6f9e74944fb)
LRU per-CPU hash | 4.10 | [8f8449384ec3](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8f8449384ec364ba2a654f11f94e754e4ff719e0) [961578b63474](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=961578b63474d13ad0e2f615fcc2901c5197dda6)
LPM trie (longest-prefix match) | 4.11 | [b95a5c4db09b](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b95a5c4db09bc7c253636cb84dc9b12c577fd5a0)
Array of maps | 4.12 | [56f668dfe00d](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=56f668dfe00dcf086734f1c42ea999398fad6572)
Hash of maps | 4.12 | [bcc6b1b7ebf8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=bcc6b1b7ebf857a9fe56202e2be3361131588c15)
Netdevice references | 4.14 | [546ac1ffb70d](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=546ac1ffb70d25b56c1126940e5ec639c4dd7413)
Socket references | 4.14 | [174a79ff9515](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=174a79ff9515f400b9a6115643dafd62a635b7e6)
Text string | _To be done?_ |
Variable-length maps | _To be done?_ |

## XDP

Feature / Driver | Kernel version | Commit
-----------------|----------------|-------
XDP core architecture | 4.8 | [6a773a15a1e8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6a773a15a1e8874e5eccd2f29190c31085912c95)
Action: drop | 4.8 | [6a773a15a1e8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6a773a15a1e8874e5eccd2f29190c31085912c95)
Action: pass on to stack | 4.8 | [6a773a15a1e8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6a773a15a1e8874e5eccd2f29190c31085912c95)
Action: direct forwarding (on same port) | 4.8 | [6ce96ca348a9](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6ce96ca348a9e949f8c43f4d3e98db367d93cffd)
Direct packet data write | 4.8 | [4acf6c0b84c9](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4acf6c0b84c91243c705303cd9ff16421914150d)
Mellanox `mlx4` driver | 4.8 | [47a38e155037](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=47a38e155037f417c5740e24ccae6482aedf4b68)
Mellanox `mlx5` driver | 4.9 | [86994156c736](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=86994156c736978d113e7927455d4eeeb2128b9f)
Netronome `nfp` driver | 4.10 | [ecd63a0217d5](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ecd63a0217d5f1e8a92f7516f5586d1177b95de2)
QLogic (Cavium) `qed*` drivers | 4.10 | [496e05170958](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=496e051709588f832d7a6a420f44f8642b308a87)
`virtio_net` driver | 4.10 | [f600b6905015](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=f600b690501550b94e83e07295d9c8b9c4c39f4e)
Broadcom `bnxt_en` driver | 4.11 | [c6d30e8391b8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c6d30e8391b85e00eb544e6cf047ee0160ee9938)
Intel `ixgbe*` drivers | 4.12 | [924708081629](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=9247080816297de4e31abb684939c0e53e3a8a67)
Cavium `thunderx` driver | 4.12 | [05c773f52b96](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=05c773f52b96ef3fbc7d9bfa21caadc6247ef7a8)
Generic XDP | 4.12 | [b5cdae3291f7](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b5cdae3291f7be7a34e75affe4c0ec1f7f328b64)
Intel `i40e` driver | 4.13 | [0c8493d90b6b](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=0c8493d90b6bb0f5c4fe9217db8f7203f24c0f28)
Action: redirect | 4.14 | [6453073987ba](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=6453073987ba392510ab6c8b657844a9312c67f7)
Support for tap | 4.14 | [761876c857cb](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=761876c857cb2ef8489fbee01907151da902af91)
Support for veth | 4.14 | [d445516966dc](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=d445516966dcb2924741b13b27738b54df2af01a)
Intel `e1000` driver | | [Not upstream yet](https://git.kernel.org/pub/scm/linux/kernel/git/ast/bpf.git/commit/?h=xdp&id=0afee87cfc800bf3317f4dc8847e6f36539b820c)
Intel `e1000e` driver | | [Not planned for upstream at this time](https://github.com/adjavon/e1000e_xdp)

## Helpers

Alphabetical order

Helper | Kernel version | Commit
-------|----------------|-------
`BPF_FUNC_clone_redirect()` | 4.2 | [3896d655f4d4](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=3896d655f4d491c67d669a15f275a39f713410f8)
`BPF_FUNC_csum_diff()` | 4.6 | [7d672345ed29](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=7d672345ed295b1356a5d9f7111da1d1d7d65867)
`BPF_FUNC_csum_update()` | 4.9 | [36bbef52c7eb](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=36bbef52c7eb646ed6247055a2acd3851e317857)
`BPF_FUNC_current_task_under_cgroup()` | 4.9 | [60d20f9195b2](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=60d20f9195b260bdf0ac10c275ae9f6016f9c069)
`BPF_FUNC_get_cgroup_classid()` | 4.3 | [8d20aabe1c76](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8d20aabe1c76cccac544d9fcc3ad7823d9e98a2d)
`BPF_FUNC_get_current_comm()` | 4.2 | [ffeedafbf023](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ffeedafbf0236f03aeb2e8db273b3e5ae5f5bc89)
`BPF_FUNC_get_current_pid_tgid()` | 4.2 | [ffeedafbf023](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ffeedafbf0236f03aeb2e8db273b3e5ae5f5bc89)
`BPF_FUNC_get_current_task()` | 4.8 | [606274c5abd8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=606274c5abd8e245add01bc7145a8cbb92b69ba8)
`BPF_FUNC_get_current_uid_gid()` | 4.2 | [ffeedafbf023](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ffeedafbf0236f03aeb2e8db273b3e5ae5f5bc89)
`BPF_FUNC_get_hash_recalc()` | 4.8 | [13c5c240f789](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=13c5c240f789bbd2bcacb14a23771491485ae61f)
`BPF_FUNC_get_numa_node_id()` | 4.10 | [2d0e30c30f84](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=2d0e30c30f84d08dc16f0f2af41f1b8a85f0755e)
`BPF_FUNC_get_prandom_u32()` | 4.1 | [03e69b508b6f](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=03e69b508b6f7c51743055c9f61d1dfeadf4b635)
`BPF_FUNC_get_route_realm()` | 4.4 | [c46646d0484f](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c46646d0484f5d08e2bede9b45034ba5b8b489cc)
`BPF_FUNC_get_smp_processor_id()` | 4.1 | [c04167ce2ca0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c04167ce2ca0ecaeaafef006cb0d65cf01b68e42)
`BPF_FUNC_get_socket_cookie()` | 4.12 | [91b8270f2a4d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=91b8270f2a4d1d9b268de90451cdca63a70052d6)
`BPF_FUNC_get_socket_uid()` | 4.12 | [6acc5c291068](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6acc5c2910689fc6ee181bf63085c5efff6a42bd)
`BPF_FUNC_get_stackid()` | 4.6 | [d5a3b1f69186](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d5a3b1f691865be576c2bffa708549b8cdccda19)
`BPF_FUNC_ktime_get_ns()` | 4.1 | [d9847d310ab4](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d9847d310ab4003725e6ed1822682e24bd406908)
`BPF_FUNC_l3_csum_replace()` | 4.1 | [91bc4822c3d6](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=91bc4822c3d61b9bb7ef66d3b77948a4f9177954)
`BPF_FUNC_l4_csum_replace()` | 4.1 | [91bc4822c3d6](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=91bc4822c3d61b9bb7ef66d3b77948a4f9177954)
`BPF_FUNC_map_delete_elem()` | 3.19 | [d0003ec01c66](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_map_lookup_elem()` | 3.19 | [d0003ec01c66](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_map_update_elem()` | 3.19 | [d0003ec01c66](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d0003ec01c667b731c139e23de3306a8b328ccf5)
`BPF_FUNC_perf_event_output()` | 4.4 | [a43eec304259](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=a43eec304259a6c637f4014a6d4767159b6a3aa3)
`BPF_FUNC_perf_event_read()` | 4.3 | [35578d798400](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=35578d7984003097af2b1e34502bc943d40c1804)
`BPF_FUNC_probe_read()` | 4.1 | [2541517c32be](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=2541517c32be2531e0da59dfd7efc1ce844644f5)
`BPF_FUNC_probe_read_str()` | 4.11 | [a5e8c07059d0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=a5e8c07059d0f0b31737408711d44794928ac218)
`BPF_FUNC_probe_write_user()` | 4.8 | [96ae52279594](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=96ae52279594470622ff0585621a13e96b700600)
`BPF_FUNC_redirect()` | 4.4 | [27b29f63058d](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=27b29f63058d26c6c1742f1993338280d5a41dc6)
`BPF_FUNC_redirect_map()` | 4.14 | [174a79ff9515](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=174a79ff9515f400b9a6115643dafd62a635b7e6)
`BPF_FUNC_set_hash()` | 4.13 | [8c4b4c7e9ff0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8c4b4c7e9ff0447995750d9329949fa082520269)
`BPF_FUNC_set_hash_invalid()` | 4.9 | [7a4b28c6cc9f](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=7a4b28c6cc9ffac50f791b99cc7e46106436e5d8)
`BPF_FUNC_setsockopt()` | 4.13 | [4b4c7e9ff044](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8c4b4c7e9ff0447995750d9329949fa082520269)
`BPF_FUNC_sk_redirect_map()` | 4.14 | [174a79ff9515](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=174a79ff9515f400b9a6115643dafd62a635b7e6)
`BPF_FUNC_skb_adjust_room()` | 4.13 | [2be7e212d541](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=2be7e212d5419a400d051c84ca9fdd083e5aacac)
`BPF_FUNC_skb_change_head()` | 4.10 | [3a0af8fd61f9](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=3a0af8fd61f90920f6fa04e4f1e9a6a73c1b4fd2)
`BPF_FUNC_skb_change_proto()` | 4.8 | [6578171a7ff0](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6578171a7ff0c31dc73258f93da7407510abf085)
`BPF_FUNC_skb_change_tail()` | 4.9 | [5293efe62df8](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=5293efe62df81908f2e90c9820c7edcc8e61f5e9)
`BPF_FUNC_skb_change_type()` | 4.8 | [d2485c4242a82](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d2485c4242a826fdf493fd3a27b8b792965b9b9e)
`BPF_FUNC_skb_get_tunnel_key()` | 4.3 | [d3aa45ce6b94](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d3aa45ce6b94c65b83971257317867db13e5f492)
`BPF_FUNC_skb_get_tunnel_opt()` | 4.6 | [14ca0751c96f](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=14ca0751c96f8d3d0f52e8ed3b3236f8b34d3460)
`BPF_FUNC_skb_load_bytes()` | 4.5 | [05c74e5e53f6](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=05c74e5e53f6cb07502c3e6a820f33e2777b6605)
`BPF_FUNC_skb_pull_data()` | 4.9 | [36bbef52c7eb](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=36bbef52c7eb646ed6247055a2acd3851e317857)
`BPF_FUNC_skb_set_tunnel_key()` | 4.3 | [d3aa45ce6b94](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=d3aa45ce6b94c65b83971257317867db13e5f492)
`BPF_FUNC_skb_set_tunnel_opt()` | 4.6 | [14ca0751c96f](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=14ca0751c96f8d3d0f52e8ed3b3236f8b34d3460)
`BPF_FUNC_skb_store_bytes()` | 4.1 | [91bc4822c3d6](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=91bc4822c3d61b9bb7ef66d3b77948a4f9177954)
`BPF_FUNC_skb_under_cgroup()` | 4.8 | [4a482f34afcc](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4a482f34afcc162d8456f449b137ec2a95be60d8)
`BPF_FUNC_skb_vlan_pop()` | 4.3 | [4e10df9a60d9](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4e10df9a60d96ced321dd2af71da558c6b750078)
`BPF_FUNC_skb_vlan_push()` | 4.3 | [4e10df9a60d9](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=4e10df9a60d96ced321dd2af71da558c6b750078)
`BPF_FUNC_sock_map_update()` | 4.14 | [174a79ff9515](https://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=174a79ff9515f400b9a6115643dafd62a635b7e6)
`BPF_FUNC_tail_call()` | 4.2 | [04fd61ab36ec](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=04fd61ab36ec065e194ab5e74ae34a5240d992bb)
`BPF_FUNC_trace_printk()` | 4.1 | [9c959c863f82](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=9c959c863f8217a2ff3d7c296e8223654d240569)
`BPF_FUNC_xdp_adjust_head()` | 4.10 | [17bedab27231](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=17bedab2723145d17b14084430743549e6943d03)
