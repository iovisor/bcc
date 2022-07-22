#!/usr/bin/python
#
# strlen_hist_ifunc.py     Histogram of system-wide strlen return values.
# This can be used instead of strlen_hist.py if strlen is indirect function.

from __future__ import print_function
from bcc import BPF
from bcc.libbcc import lib, bcc_symbol, bcc_symbol_option

import ctypes as ct
import sys
import time

NAME = 'c'
SYMBOL = 'strlen'
STT_GNU_IFUNC = 1 << 10

HIST_BPF_TEXT = """
#include <uapi/linux/ptrace.h>
BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(bpf_log2l(PT_REGS_RC(ctx)));
    return 0;
}
"""

SUBMIT_FUNC_ADDR_BPF_TEXT = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(impl_func_addr);
void submit_impl_func_addr(struct pt_regs *ctx) {
    u64 addr = PT_REGS_RC(ctx);
    impl_func_addr.perf_submit(ctx, &addr, sizeof(addr));
}


BPF_PERF_OUTPUT(resolv_func_addr);
int submit_resolv_func_addr(struct pt_regs *ctx) {
    u64 rip = PT_REGS_IP(ctx);
    resolv_func_addr.perf_submit(ctx, &rip, sizeof(rip));
    return 0;
}
"""


def get_indirect_function_sym(module, symname):
    sym = bcc_symbol()
    sym_op = bcc_symbol_option()
    sym_op.use_debug_file = 1
    sym_op.check_debug_file_crc = 1
    sym_op.lazy_symbolize = 1
    sym_op.use_symbol_type = STT_GNU_IFUNC
    if lib.bcc_resolve_symname(
            module.encode(),
            symname.encode(),
            0x0,
            0,
            ct.byref(sym_op),
            ct.byref(sym),
    ) < 0:
        return None
    else:
        return sym


def set_impl_func_addr(cpu, data, size):
    addr = ct.cast(data, ct.POINTER(ct.c_uint64)).contents.value
    global impl_func_addr
    impl_func_addr = addr


def set_resolv_func_addr(cpu, data, size):
    addr = ct.cast(data, ct.POINTER(ct.c_uint64)).contents.value
    global resolv_func_addr
    resolv_func_addr = addr


def find_impl_func_offset(ifunc_symbol):
    b = BPF(text=SUBMIT_FUNC_ADDR_BPF_TEXT)
    b.attach_uprobe(name=NAME, sym=SYMBOL, fn_name=b'submit_resolv_func_addr')
    b['resolv_func_addr'].open_perf_buffer(set_resolv_func_addr)
    b.attach_uretprobe(name=NAME, sym=SYMBOL, fn_name=b"submit_impl_func_addr")
    b['impl_func_addr'].open_perf_buffer(set_impl_func_addr)

    print('wait for the first {} call'.format(SYMBOL))
    while True:
        try:
            if resolv_func_addr and impl_func_addr:
                b.detach_uprobe(name=NAME, sym=SYMBOL)
                b.detach_uretprobe(name=NAME, sym=SYMBOL)
                b.cleanup()
                break
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
    print('IFUNC resolution of {} is performed'.format(SYMBOL))
    print('resolver function address: {:#x}'.format(resolv_func_addr))
    print('resolver function offset: {:#x}'.format(ifunc_symbol.offset))
    print('function implementation address: {:#x}'.format(impl_func_addr))
    impl_func_offset = impl_func_addr - resolv_func_addr + ifunc_symbol.offset
    print('function implementation offset: {:#x}'.format(impl_func_offset))
    return impl_func_offset


def main():
    ifunc_symbol = get_indirect_function_sym(NAME, SYMBOL)
    if not ifunc_symbol:
        sys.stderr.write('{} is not an indirect function. abort!\n'.format(SYMBOL))
        exit(1)

    impl_func_offset = find_impl_func_offset(ifunc_symbol)

    b = BPF(text=HIST_BPF_TEXT)
    b.attach_uretprobe(name=ct.cast(ifunc_symbol.module, ct.c_char_p).value,
                       addr=impl_func_offset,
                       fn_name=b'count')
    dist = b['dist']
    try:
        while True:
            time.sleep(1)
            print('%-8s\n' % time.strftime('%H:%M:%S'), end='')
            dist.print_log2_hist(SYMBOL + ' return:')
            dist.clear()

    except KeyboardInterrupt:
        pass


resolv_func_addr = 0
impl_func_addr = 0

main()
