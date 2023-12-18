#!/usr/bin/python
#
# ppchcalls   Summarize ppc hcalls stats.
#
# Initial version migrating perf based tool to ebpf with additional hcalls,
# inspired by existing bcc tool for syscalls.
#
#

from time import sleep, strftime
import argparse
import errno
import itertools
import sys
import signal
from bcc import BPF

hcall_table = {
    4: 'H_REMOVE',
    8: 'H_ENTER',
    12: 'H_READ',
    16: 'H_CLEAR_MOD',
    20: 'H_CLEAR_REF',
    24: 'H_PROTECT',
    28: 'H_GET_TCE',
    32: 'H_PUT_TCE',
    36: 'H_SET_SPRG0',
    40: 'H_SET_DABR',
    44: 'H_PAGE_INIT',
    48: 'H_SET_ASR',
    52: 'H_ASR_ON',
    56: 'H_ASR_OFF',
    60: 'H_LOGICAL_CI_LOAD',
    64: 'H_LOGICAL_CI_STORE',
    68: 'H_LOGICAL_CACHE_LOAD',
    72: 'H_LOGICAL_CACHE_STORE',
    76: 'H_LOGICAL_ICBI',
    80: 'H_LOGICAL_DCBF',
    84: 'H_GET_TERM_CHAR',
    88: 'H_PUT_TERM_CHAR',
    92: 'H_REAL_TO_LOGICAL',
    96: 'H_HYPERVISOR_DATA',
    100: 'H_EOI',
    104: 'H_CPPR',
    108: 'H_IPI',
    112: 'H_IPOLL',
    116: 'H_XIRR',
    120: 'H_MIGRATE_DMA',
    124: 'H_PERFMON',
    220: 'H_REGISTER_VPA',
    224: 'H_CEDE',
    228: 'H_CONFER',
    232: 'H_PROD',
    236: 'H_GET_PPP',
    240: 'H_SET_PPP',
    244: 'H_PURR',
    248: 'H_PIC',
    252: 'H_REG_CRQ',
    256: 'H_FREE_CRQ',
    260: 'H_VIO_SIGNAL',
    264: 'H_SEND_CRQ',
    272: 'H_COPY_RDMA',
    276: 'H_REGISTER_LOGICAL_LAN',
    280: 'H_FREE_LOGICAL_LAN',
    284: 'H_ADD_LOGICAL_LAN_BUFFER',
    288: 'H_SEND_LOGICAL_LAN',
    292: 'H_BULK_REMOVE',
    304: 'H_MULTICAST_CTRL',
    308: 'H_SET_XDABR',
    312: 'H_STUFF_TCE',
    316: 'H_PUT_TCE_INDIRECT',
    332: 'H_CHANGE_LOGICAL_LAN_MAC',
    336: 'H_VTERM_PARTNER_INFO',
    340: 'H_REGISTER_VTERM',
    344: 'H_FREE_VTERM',
    348: 'H_RESET_EVENTS',
    352: 'H_ALLOC_RESOURCE',
    356: 'H_FREE_RESOURCE',
    360: 'H_MODIFY_QP',
    364: 'H_QUERY_QP',
    368: 'H_REREGISTER_PMR',
    372: 'H_REGISTER_SMR',
    376: 'H_QUERY_MR',
    380: 'H_QUERY_MW',
    384: 'H_QUERY_HCA',
    388: 'H_QUERY_PORT',
    392: 'H_MODIFY_PORT',
    396: 'H_DEFINE_AQP1',
    400: 'H_GET_TRACE_BUFFER',
    404: 'H_DEFINE_AQP0',
    408: 'H_RESIZE_MR',
    412: 'H_ATTACH_MCQP',
    416: 'H_DETACH_MCQP',
    420: 'H_CREATE_RPT',
    424: 'H_REMOVE_RPT',
    428: 'H_REGISTER_RPAGES',
    432: 'H_DISABLE_AND_GET',
    436: 'H_ERROR_DATA',
    440: 'H_GET_HCA_INFO',
    444: 'H_GET_PERF_COUNT',
    448: 'H_MANAGE_TRACE',
    456: 'H_GET_CPU_CHARACTERISTICS',
    468: 'H_FREE_LOGICAL_LAN_BUFFER',
    472: 'H_POLL_PENDING',
    484: 'H_QUERY_INT_STATE',
    580: 'H_ILLAN_ATTRIBUTES',
    592: 'H_MODIFY_HEA_QP',
    596: 'H_QUERY_HEA_QP',
    600: 'H_QUERY_HEA',
    604: 'H_QUERY_HEA_PORT',
    608: 'H_MODIFY_HEA_PORT',
    612: 'H_REG_BCMC',
    616: 'H_DEREG_BCMC',
    620: 'H_REGISTER_HEA_RPAGES',
    624: 'H_DISABLE_AND_GET_HEA',
    628: 'H_GET_HEA_INFO',
    632: 'H_ALLOC_HEA_RESOURCE',
    644: 'H_ADD_CONN',
    648: 'H_DEL_CONN',
    664: 'H_JOIN',
    672: 'H_VASI_SIGNAL',
    676: 'H_VASI_STATE',
    680: 'H_VIOCTL',
    688: 'H_ENABLE_CRQ',
    696: 'H_GET_EM_PARMS',
    720: 'H_SET_MPP',
    724: 'H_GET_MPP',
    732: 'H_REG_SUB_CRQ',
    736: 'H_FREE_SUB_CRQ',
    740: 'H_SEND_SUB_CRQ',
    744: 'H_SEND_SUB_CRQ_INDIRECT',
    748: 'H_HOME_NODE_ASSOCIATIVITY',
    756: 'H_BEST_ENERGY',
    764: 'H_XIRR_X',
    768: 'H_RANDOM',
    772: 'H_COP',
    788: 'H_GET_MPP_X',
    796: 'H_SET_MODE',
    808: 'H_BLOCK_REMOVE',
    856: 'H_CLEAR_HPT',
    864: 'H_REQUEST_VMC',
    876: 'H_RESIZE_HPT_PREPARE',
    880: 'H_RESIZE_HPT_COMMIT',
    892: 'H_REGISTER_PROC_TBL',
    896: 'H_SIGNAL_SYS_RESET',
    904: 'H_ALLOCATE_VAS_WINDOW',
    908: 'H_MODIFY_VAS_WINDOW',
    912: 'H_DEALLOCATE_VAS_WINDOW',
    916: 'H_QUERY_VAS_WINDOW',
    920: 'H_QUERY_VAS_CAPABILITIES',
    924: 'H_QUERY_NX_CAPABILITIES',
    928: 'H_GET_NX_FAULT',
    936: 'H_INT_GET_SOURCE_INFO',
    940: 'H_INT_SET_SOURCE_CONFIG',
    944: 'H_INT_GET_SOURCE_CONFIG',
    948: 'H_INT_GET_QUEUE_INFO',
    952: 'H_INT_SET_QUEUE_CONFIG',
    956: 'H_INT_GET_QUEUE_CONFIG',
    960: 'H_INT_SET_OS_REPORTING_LINE',
    964: 'H_INT_GET_OS_REPORTING_LINE',
    968: 'H_INT_ESB',
    972: 'H_INT_SYNC',
    976: 'H_INT_RESET',
    996: 'H_SCM_READ_METADATA',
    1000: 'H_SCM_WRITE_METADATA',
    1004: 'H_SCM_BIND_MEM',
    1008: 'H_SCM_UNBIND_MEM',
    1012: 'H_SCM_QUERY_BLOCK_MEM_BINDING',
    1016: 'H_SCM_QUERY_LOGICAL_MEM_BINDING',
    1020: 'H_SCM_UNBIND_ALL',
    1024: 'H_SCM_HEALTH',
    1048: 'H_SCM_PERFORMANCE_STATS',
    1052: 'H_PKS_GET_CONFIG',
    1056: 'H_PKS_SET_PASSWORD',
    1060: 'H_PKS_GEN_PASSWORD',
    1068: 'H_PKS_WRITE_OBJECT',
    1072: 'H_PKS_GEN_KEY',
    1076: 'H_PKS_READ_OBJECT',
    1080: 'H_PKS_REMOVE_OBJECT',
    1084: 'H_PKS_CONFIRM_OBJECT_FLUSHED',
    1096: 'H_RPT_INVALIDATE',
    1100: 'H_SCM_FLUSH',
    1104: 'H_GET_ENERGY_SCALE_INFO',
    1108: 'H_PKS_SIGNED_UPDATE',
    1116: 'H_WATCHDOG',
    # Platform specific hcalls used by KVM on PowerVM
    1120: 'H_GUEST_GET_CAPABILITIES',
    1124: 'H_GUEST_SET_CAPABILITIES',
    1136: 'H_GUEST_CREATE',
    1140: 'H_GUEST_CREATE_VCPU',
    1144: 'H_GUEST_GET_STATE',
    1148: 'H_GUEST_SET_STATE',
    1152: 'H_GUEST_RUN_VCPU',
    1156: 'H_GUEST_COPY_MEMORY',
    1160: 'H_GUEST_DELETE',
    # Platform-specific hcalls used by the Ultravisor
    61184: 'H_SVM_PAGE_IN',
    61188: 'H_SVM_PAGE_OUT',
    61192: 'H_SVM_INIT_START',
    61196: 'H_SVM_INIT_DONE',
    61204: 'H_SVM_INIT_ABORT',
    # Platform specific hcalls used by KVM
    61440: 'H_RTAS',
    # Platform specific hcalls used by QEMU/SLOF
    61441: 'H_LOGICAL_MEMOP',
    61442: 'H_CAS',
    61443: 'H_UPDATE_DT',
    # Platform specific hcalls provided by PHYP
    61560: 'H_GET_24X7_CATALOG_PAGE',
    61564: 'H_GET_24X7_DATA',
    61568: 'H_GET_PERF_COUNTER_INFO',
    # Platform-specific hcalls used for nested HV KVM
    63488: 'H_SET_PARTITION_TABLE',
    63492: 'H_ENTER_NESTED',
    63496: 'H_TLB_INVALIDATE',
    63500: 'H_COPY_TOFROM_GUEST',
}

def hcall_table_lookup(opcode):
        if (opcode in hcall_table):
                return hcall_table[opcode]
        else:
                return opcode

if sys.version_info.major < 3:
    izip_longest = itertools.izip_longest
else:
    izip_longest = itertools.zip_longest

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)


parser = argparse.ArgumentParser(
    description="Summarize ppc hcall counts and latencies.")
parser.add_argument("-p", "--pid", type=int,
    help="trace only this pid")
parser.add_argument("-t", "--tid", type=int,
    help="trace only this tid")
parser.add_argument("-i", "--interval", type=int,
    help="print summary at this interval (seconds)")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-T", "--top", type=int, default=10,
    help="print only the top hcalls by count or latency")
parser.add_argument("-x", "--failures", action="store_true",
    help="trace only failed hcalls (return < 0)")
parser.add_argument("-e", "--errno", type=handle_errno,
    help="trace only hcalls that return this error (numeric or EPERM, etc.)")
parser.add_argument("-L", "--latency", action="store_true",
    help="collect hcall latency")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="display latency in milliseconds (default: microseconds)")
parser.add_argument("-P", "--process", action="store_true",
    help="count by process and not by hcall")
parser.add_argument("-l", "--list", action="store_true",
    help="print list of recognized hcalls and exit")
parser.add_argument("--hcall", type=str,
    help="trace this hcall only (use option -l to get all recognized hcalls)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

hcall_nr = -1
if args.hcall is not None:
    for key, value in hcall_table.items():
        if args.hcall == value:
            hcall_nr = key
            print("hcall %s , hcall_nr =%d" % (args.hcall, hcall_nr))
            break
    if hcall_nr == -1:
        print("Error: hcall '%s' not found. Exiting." % args.hcall)
        sys.exit(1)

if args.list:
    for grp in izip_longest(*(iter(sorted(hcall_table.values())),) * 4):
        print("   ".join(["%-25s" % s for s in grp if s is not None]))
    sys.exit(0)

text = """
#ifdef LATENCY
struct data_t {
    u64 count;
    u64 min;
    u64 max;
    u64 total_ns;
};

BPF_HASH(start, u64, u64);
BPF_HASH(ppc_data, u32, struct data_t);
#else
BPF_HASH(ppc_data, u32, u64);
#endif

#ifdef LATENCY
RAW_TRACEPOINT_PROBE(hcall_entry) {
    // TP_PROTO(unsigned long opcode, unsigned long *args),
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

#ifdef FILTER_HCALL_NR
if (ctx->args[0] != FILTER_HCALL_NR)
    return 0;
#endif

#ifdef FILTER_PID
    if (pid != FILTER_PID)
        return 0;
#endif

#ifdef FILTER_TID
    if (tid != FILTER_TID)
        return 0;
#endif

    u64 t = bpf_ktime_get_ns();
    start.update(&pid_tgid, &t);
    return 0;
}
#endif

RAW_TRACEPOINT_PROBE(hcall_exit) {
    // TP_PROTO(unsigned long opcode, long retval, unsigned long *retbuf)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

#ifdef FILTER_HCALL_NR
    if (ctx->args[0] != FILTER_HCALL_NR)
        return 0;
#endif

#ifdef FILTER_PID
    if (pid != FILTER_PID)
        return 0;
#endif

#ifdef FILTER_TID
    if (tid != FILTER_TID)
        return 0;
#endif

#ifdef FILTER_FAILED
    if (ctx->args[1] >= 0)
        return 0;
#endif

#ifdef FILTER_ERRNO
    if (ctx->args[1] != -FILTER_ERRNO)
        return 0;
#endif

#ifdef BY_PROCESS
    u32 key = pid_tgid >> 32;
#else
    u32 key = (unsigned long) ctx->args[0];
#endif

#ifdef LATENCY
    struct data_t *val, zero = {};
    u64 delta = 0;
    u64 *start_ns = start.lookup(&pid_tgid);
    if (!start_ns)
        return 0;

    val = ppc_data.lookup_or_try_init(&key, &zero);
    if (val) {
        val->count++;
        delta = bpf_ktime_get_ns() - *start_ns;
        if (val->min) {
            if(val->min > delta)
                val->min = delta;
        } else {
                val->min = delta;
        }
        if (val->max) {
            if(val->max < delta)
                val->max = delta;
        } else {
                val->max = delta;
        }
        val->total_ns += delta;
    }
#else
    u64 *val, zero = 0;
    val = ppc_data.lookup_or_try_init(&key, &zero);
    if (val) {
        ++(*val);
    }
#endif
    return 0;
}
"""

if args.pid:
    text = ("#define FILTER_PID %d\n" % args.pid) + text
elif args.tid:
    text = ("#define FILTER_TID %d\n" % args.tid) + text
if args.failures:
    text = "#define FILTER_FAILED\n" + text
if args.errno:
    text = "#define FILTER_ERRNO %d\n" % abs(args.errno) + text
if args.latency:
    text = "#define LATENCY\n" + text
if args.process:
    text = "#define BY_PROCESS\n" + text
if args.hcall is not None:
    text = ("#define FILTER_HCALL_NR %d\n" % hcall_nr) + text
if args.ebpf:
    print(text)
    exit()

bpf = BPF(text=text)

def print_stats():
    if args.latency:
        ppc_print_latency_stats()
    else:
        print_ppc_count_stats()

ppc_agg_colname = "PID    COMM" if args.process else "PPC HCALL"
min_time_colname = "MIN (ms)" if args.milliseconds else "MIN (us)"
max_time_colname = "MAX (ms)" if args.milliseconds else "MAX (us)"
avg_time_colname = "AVG (ms)" if args.milliseconds else "AVG (us)"

def comm_for_pid(pid):
    try:
        return open("/proc/%d/comm" % pid, "r").read().strip()
    except Exception:
        return "[unknown]"

def agg_colval(key):
    if args.process:
        return "%-6d %-15s" % (key.value, comm_for_pid(key.value))
    else:
        return hcall_table_lookup(key.value)

def print_ppc_count_stats():
    data = bpf["ppc_data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-45s %8s" % (ppc_agg_colname, "COUNT"))
    for k, v in sorted(data.items(), key=lambda kv: -kv[1].value)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        print("%-45s %8d" % (agg_colval(k), v.value))
    print("")
    data.clear()

def ppc_print_latency_stats():
    data = bpf["ppc_data"]
    print("[%s]" % strftime("%H:%M:%S"))
    print("%-45s %8s %17s %17s %17s" % (ppc_agg_colname, "COUNT",
          min_time_colname, max_time_colname, avg_time_colname))
    for k, v in sorted(data.items(),
                       key=lambda kv: -kv[1].count)[:args.top]:
        if k.value == 0xFFFFFFFF:
            continue    # happens occasionally, we don't need it
        print(("%-45s %8d " + ("%17.6f" if args.milliseconds else "%17.3f ") +
                              ("%17.6f" if args.milliseconds else "%17.3f ") +
                              ("%17.6f" if args.milliseconds else "%17.3f")) %
               (agg_colval(k), v.count,
                v.min / (1e6 if args.milliseconds else 1e3),
                v.max / (1e6 if args.milliseconds else 1e3),
                (v.total_ns / v.count) / (1e6 if args.milliseconds else 1e3)))
    print("")
    data.clear()

if args.hcall is not None:
    print("Tracing %sppc hcall '%s'... Ctrl+C to quit." %
        ("failed " if args.failures else "", args.hcall))
else:
    print("Tracing %sppc hcalls, printing top %d... Ctrl+C to quit." %
        ("failed " if args.failures else "", args.top))
exiting = 0 if args.interval else 1
seconds = 0
while True:
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1

    print_stats()

    if exiting:
        print("Detaching...")
        exit()
