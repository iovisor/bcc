#ifndef __TCPDROP_H
#define __TCPDROP_H

#define TASK_COMM_LEN 16

struct event {
	__u64 timestamp;
	__u32 pid;
	__s32 drop_reason;
	__u32 ip_version;
	union {
		__u32 saddr_v4;
		__u32 saddr_v6[4];
	};
	union {
		__u32 daddr_v4;
		__u32 daddr_v6[4];
	};
	__u16 sport;
	__u16 dport;
	__u8 state;
	__u8 tcpflags;
	char comm[TASK_COMM_LEN];
	__u32 stack_id;
};

#endif /* __TCPDROP_H */