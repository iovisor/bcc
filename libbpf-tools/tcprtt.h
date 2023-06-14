/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPRTT_H
#define __TCPRTT_H

#define MAX_SLOTS	27
#define IPV6_LEN	16

struct hist {
	__u64 latency;
	__u64 cnt;
	__u32 slots[MAX_SLOTS];
};

struct hist_key {
	__u16 family;
	__u8 addr[IPV6_LEN];
};

#endif /* __TCPRTT_H */
