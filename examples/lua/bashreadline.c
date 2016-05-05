#include <uapi/linux/ptrace.h>

struct str_t {
	u64 pid;
	char str[80];
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ctx)
{
	struct str_t data  = {};
	u32 pid;
	if (!ctx->PT_REGS_RC)
		return 0;
	pid = bpf_get_current_pid_tgid();
	data.pid = pid;
	bpf_probe_read(&data.str, sizeof(data.str), (void *)ctx->PT_REGS_RC);
	events.perf_submit(ctx,&data,sizeof(data));
	return 0;
};
