/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BINDSNOOP_H
#define __BINDSNOOP_H

#define TASK_COMM_LEN	16

struct bind_event {
	__u8 addr[16];
	__u64 ts_us;
	__u32 pid;
	__u32 bound_dev_if;
	int ret;
	__u16 port;
	__u16 proto;
	__u8 opts;
	__u8 ver;
	char task[TASK_COMM_LEN];
};

union bind_options {
	__u8 data;
	struct {
		__u8 freebind : 1;
		__u8 transparent : 1;
		__u8 bind_address_no_port : 1;
		__u8 reuseaddress : 1;
		__u8 reuseport : 1;
	} fields;
};

#endif /* __BINDSNOOP_H */
