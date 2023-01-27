#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	u64 id;
	pid_t pid, tgid;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;

	bpf_printk("malloc enter - pid:%d, tgid:%d\n", pid, tgid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
