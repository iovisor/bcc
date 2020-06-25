#!/usr/bin/python3

import sys
import time

from bcc import BPF

src = r"""
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

struct event {
    char filename[64];
    int dfd;
    int flags;
    int mode;
};

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    int zero = 0;

    struct event *event = buffer.ringbuf_reserve(sizeof(struct event));
    if (!event) {
        return 1;
    }

    bpf_probe_read_user_str(event->filename, sizeof(event->filename), args->filename);

    event->dfd = args->dfd;
    event->flags = args->flags;
    event->mode = args->mode;

    buffer.ringbuf_submit(event, 0);
    // or, to discard: buffer.ringbuf_discard(event, 0);

    return 0;
}
"""

b = BPF(text=src)

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    print("%-64s %10d %10d %10d" % (event.filename.decode('utf-8'), event.dfd, event.flags, event.mode))

b['buffer'].open_ring_buffer(callback)

print("Printing openat() calls, ctrl-c to exit.")

print("%-64s %10s %10s %10s" % ("FILENAME", "DIR_FD", "FLAGS", "MODE"))

try:
    while 1:
        b.ring_buffer_consume()
        time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()
