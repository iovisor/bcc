#!/usr/bin/env python3
#
# This programs creates CTF events from do_sys_open

from bcc import BPF
import ctypes as ct
import babeltrace.writer as btw
import babeltrace.common
import tempfile

trace_path = tempfile.mkdtemp()

print('trace path: {}'.format(trace_path))

# our writer
writer = btw.Writer(trace_path)

# create one default clock and register it to the writer
clock = btw.Clock('my_clock')
clock.description = 'this is my clock'
writer.add_clock(clock)

# create one default stream class and assign our clock to it
stream_class = btw.StreamClass('my_stream')
stream_class.clock = clock

# create one default event class
event_class = btw.EventClass('do_sys_open')

# create one 32-bit unsigned integer field
uint32_field_decl = btw.IntegerFieldDeclaration(32)
uint32_field_decl.signed = False

# create one 64-bit unsigned integer field
uint64_field_decl = btw.IntegerFieldDeclaration(64)
uint64_field_decl.signed = False

# string field declaration
string_field_decl = btw.StringFieldDeclaration()
string_field_decl.encoding = babeltrace.common.CTFStringEncoding.UTF8

event_class.add_field(uint32_field_decl, 'pid')
event_class.add_field(uint64_field_decl, 'ts')
event_class.add_field(string_field_decl, 'comm')
event_class.add_field(string_field_decl, 'filename')

stream_class.add_event_class(event_class)

stream = writer.create_stream(stream_class)

# BPF program
prog = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};
BPF_PERF_OUTPUT(events);

int handler(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)PT_REGS_PARM2(ctx));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="do_sys_open", fn_name="handler")

# Get output data
TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255        # uapi/linux/limits.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("fname", ct.c_char * NAME_MAX)]


# Print event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    time_s = event.ts / 1000000000
    print('{}  {}  {}  {}'.format(time_s, event.comm.decode(), event.pid, event.fname.decode()))

# Write event in CTF
def write_event(cpu, data, size):
    ctfevent = btw.Event(event_class)
    event = ct.cast(data, ct.POINTER(Data)).contents
    ctfevent.payload('ts').value = event.ts
    ctfevent.payload('pid').value = event.pid
    ctfevent.payload('comm').value = event.comm.decode()
    ctfevent.payload('filename').value = event.fname.decode()
    stream.append_event(ctfevent)
    stream.flush()

# We write the event for now
b["events"].open_perf_buffer(write_event)
while 1:
    b.kprobe_poll()
