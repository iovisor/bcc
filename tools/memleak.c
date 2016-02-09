#include <uapi/linux/ptrace.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int num_frames;
        u64 callstack[MAX_STACK_SIZE];
};

BPF_HASH(sizes, u64);
BPF_HASH(allocs, u64, struct alloc_info_t);

// Adapted from https://github.com/iovisor/bcc/tools/offcputime.py
static u64 get_frame(u64 *bp) {
        if (*bp) {
                // The following stack walker is x86_64 specific
                u64 ret = 0;
                if (bpf_probe_read(&ret, sizeof(ret), (void *)(*bp+8)))
                        return 0;
                if (bpf_probe_read(bp, sizeof(*bp), (void *)*bp))
                        *bp = 0;
                return ret;
        }
        return 0;
}
static int grab_stack(struct pt_regs *ctx, struct alloc_info_t *info)
{
        int depth = 0;
        u64 bp = ctx->bp;
        GRAB_ONE_FRAME
        return depth;
}

int alloc_enter(struct pt_regs *ctx, size_t size)
{
        // Ideally, this should use a random number source, such as 
        // BPF_FUNC_get_prandom_u32, but that's currently not supported
        // by the bcc front-end.
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\n", size);
        return 0;
}

int alloc_exit(struct pt_regs *ctx)
{
        u64 address = ctx->ax;
        u64 pid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&pid);

        info.timestamp_ns = bpf_ktime_get_ns();
        info.num_frames = grab_stack(ctx, &info) - 2;
        allocs.update(&address, &info);
        
        if (SHOULD_PRINT)
                bpf_trace_printk("alloc exited, size = %lu, result = %lx, frames = %d\n", info.size, address, info.num_frames);
        return 0;
}

int free_enter(struct pt_regs *ctx, void *address)
{
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);

        if (SHOULD_PRINT)
                bpf_trace_printk("free entered, address = %lx, size = %lu\n", address, info->size);
        return 0;
}
