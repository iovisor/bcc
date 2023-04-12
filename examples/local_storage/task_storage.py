#!/usr/bin/python3

from bcc import BPF

source = r"""
BPF_TASK_STORAGE(task_storage_map, __u64);

KFUNC_PROBE(inet_listen)
{
	__u64 ts = bpf_ktime_get_ns();

	/* save timestamp to local storage on function entry */
	task_storage_map.task_storage_get(bpf_get_current_task_btf(), &ts, BPF_LOCAL_STORAGE_GET_F_CREATE);

	bpf_trace_printk("inet_listen entry: store timestamp %lld", ts);
	return 0;
}

KRETFUNC_PROBE(inet_listen)
{
	__u64 *ts;

	/* retrieve timestamp stored at local storage on function exit */
	ts = task_storage_map.task_storage_get(bpf_get_current_task_btf(), 0, 0);
	if (!ts)
		return 0;

	/* delete timestamp from local storage */
	task_storage_map.task_storage_delete(bpf_get_current_task_btf());

	/* calculate latency */
	bpf_trace_printk("inet_listen exit: cost %lldus", (bpf_ktime_get_ns() - *ts) / 1000);
	return 0;
}
"""

b = BPF(text=source)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
