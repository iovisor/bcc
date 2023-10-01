#!/usr/bin/env python
from __future__ import print_function
from bcc import BPF
import argparse
import binascii
import sys


def int_in_range(minval, maxval):
    def validator(val):
        try:
            intval = int(val)
        except ValueError:
            raise argparse.ArgumentTypeError("Incorrect int value %r" % val)
        else:
            if minval <= intval <= maxval:
                return intval
            else:
                raise argparse.ArgumentTypeError("Value should be in in range [%d, %d]" % (minval, maxval))

    return validator


class HelpFormatter(argparse.RawDescriptionHelpFormatter,
                    argparse.ArgumentDefaultsHelpFormatter):
    pass


examples = """examples:
    ./gotlskeylog /path/someapp                   # trace someapp and log TLS to stdout
    ./gotlskeylog -o /tmp/tls.log /path/someapp   # trace someapp and write keys into tls.log file
    ./gotlskeylog /path/foo /path/bar             # trace TLS keys from foo and bar Go apps
    ./gotlskeylog -p 181 someapp                  # trace only PID 181 of someapp
    ./gotlskeylog -u 1000 someapp                 # trace only UID 1000
"""

parser = argparse.ArgumentParser(
    description="Intercept TLS keys from Go app and write them in a SSLKEYLOGFILE format",
    formatter_class=HelpFormatter,
    epilog=examples
)
parser.add_argument("-p", "--pid", type=int, default=None, help="Trace this PID only")
parser.add_argument("-u", "--uid", type=int, default=None, help="Trace this UID only")
parser.add_argument("--max-label-size", type=int_in_range(32, 128), default=32,
                    help="Max label size, should be in [32, 128] range")
parser.add_argument("--max-client-random-size", type=int_in_range(32, 256),
                    default=32, help="Max size of client_random, should be in [32, 256]")
parser.add_argument("--max-secret-size", type=int_in_range(48, 256), default=64,
                    help="Max secret size, should be in [48, 256] range")
parser.add_argument("-o", "--output", type=argparse.FileType(mode="w"),
                    default=sys.stdout, help="Output file to use instead of stdout")
parser.add_argument("path", type=str, nargs='+')
args = parser.parse_args()


BPF_PROGRAM_TEMPLATE = """
#include <linux/ptrace.h>

// https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md
#define GOLANG_REGS_PARM1(x) ((x)->ax)
#define GOLANG_REGS_PARM2(x) ((x)->bx)
#define GOLANG_REGS_PARM3(x) ((x)->cx)
#define GOLANG_REGS_PARM4(x) ((x)->di)
#define GOLANG_REGS_PARM5(x) ((x)->si)
#define GOLANG_REGS_PARM6(x) ((x)->r8)
#define GOLANG_REGS_PARM7(x) ((x)->r9)
#define GOLANG_REGS_PARM8(x) ((x)->r10)
#define GOLANG_REGS_PARM9(x) ((x)->r11)

#define MAX_LABEL_SIZE __MAX_LABEL_SIZE__
#define MAX_CLIENT_RANDOM_SIZE __MAX_CLIENT_RANDOM_SIZE__
#define MAX_SECRET_SIZE __MAX_SECRET_SIZE__

struct probe_KeyLogData {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    u64 label_size;
    u64 client_random_size;
    u64 secret_size;
    char label[MAX_LABEL_SIZE];
    u8 client_random[MAX_CLIENT_RANDOM_SIZE];
    u8 secret[MAX_SECRET_SIZE];
};

BPF_PERCPU_ARRAY(keylog_data, struct probe_KeyLogData, 1);
BPF_PERF_OUTPUT(perf_KeylogOut);

int probe_WriteKeyLog(struct pt_regs *ctx) {
    u64 len;
    u64 addr;
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    u32 uid = bpf_get_current_uid_gid();

    __PID_FILTER__
    __UID_FILTER__

    struct probe_KeyLogData *data = keylog_data.lookup(&zero);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    len = GOLANG_REGS_PARM3(ctx);
    data->label_size = len;
    addr = GOLANG_REGS_PARM2(ctx);
    bpf_probe_read_user(&data->label, min((size_t)len, (size_t)MAX_LABEL_SIZE), (char *)addr);
    // client random GOLANG_REGS_PARM4 GOLANG_REGS_PARM5 (rdi addr, rsi len, r8 cap)
    addr = GOLANG_REGS_PARM4(ctx);
    len= GOLANG_REGS_PARM5(ctx); /* parm6 is cap(clientRandom) */
    data->client_random_size = len;
    if (len <= MAX_CLIENT_RANDOM_SIZE) {
        bpf_probe_read_user(&data->client_random, len, (u8*)addr);
    }
    addr = GOLANG_REGS_PARM7(ctx);
    len= GOLANG_REGS_PARM8(ctx);
    data->secret_size = len;
    if (len <= MAX_SECRET_SIZE) {
        bpf_probe_read_user(&data->secret, len, (u8*)addr);
    }
    perf_KeylogOut.perf_submit(ctx, data, sizeof(struct probe_KeyLogData));
    return 0;
}
"""


def generate_program(args):
    prog = BPF_PROGRAM_TEMPLATE.replace('__MAX_LABEL_SIZE__', str(args.max_label_size))
    prog = prog.replace('__MAX_CLIENT_RANDOM_SIZE__', str(args.max_client_random_size))
    prog = prog.replace('__MAX_SECRET_SIZE__', str(args.max_secret_size))
    if args.pid is None:
        prog = prog.replace('__PID_FILTER__', '')
    else:
        prog = prog.replace('__PID_FILTER__', 'if (pid != %d) { return 0; }' % args.pid)

    if args.uid is None:
        prog = prog.replace('__UID_FILTER__', '')
    else:
        prog = prog.replace('__UID_FILTER__', 'if (uid != %d) { return 0; }' % args.uid)

    return prog


ebpf = BPF(text=generate_program(args))
for path in args.path:
    ebpf.attach_uprobe(name=path, sym="crypto/tls.(*Config).writeKeyLog",
        fn_name="probe_WriteKeyLog")


def print_event(cpu, data, size):
    event = ebpf["perf_KeylogOut"].event(data)
    label = event.label[:min(event.label_size, args.max_label_size)]
    client_random = event.client_random[:min(event.client_random_size, args.max_client_random_size)]
    secret = event.secret[:min(event.secret_size, args.max_secret_size)]

    label_truncated = event.label_size > args.max_label_size
    client_random_truncated = event.client_random_size > args.max_client_random_size
    secret_truncated = event.secret_size > args.max_secret_size

    # do not log truncated keys
    if not (label_truncated or client_random_truncated or secret_truncated):
        args.output.write("%s %s %s\n" % (
            label.decode("utf-8"),
            binascii.hexlify(bytearray(client_random)).decode("utf-8"),
            binascii.hexlify(bytearray(secret)).decode("utf-8"))
        )
        args.output.flush()
    else:
        # notify about truncated keys, so user could adjust buffer sizes
        truncated_msg = ["WARNING: (pid: %d, uid %d)" % (event.pid, event.uid)]
        if label_truncated:
            truncated_msg.append(" label truncated (size %d)" % event.label_size)
        if client_random_truncated:
            truncated_msg.append(" client_random truncated (size %d)" % event.client_random_size)
        if secret_truncated:
            truncated_msg.append(" secret truncated (size %d)" % event.secret_size)

        truncated_msg.append("\n")
        sys.stderr.write("".join(truncated_msg))


try:
    ebpf["perf_KeylogOut"].open_perf_buffer(print_event)
    while True:
        try:
            ebpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
finally:
    args.output.close()
