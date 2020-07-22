#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN	16

struct event {
	union {
		__u32 saddr_v4;
		unsigned __int128 saddr_v6;
	};
	union {
		__u32 daddr_v4;
		unsigned __int128 daddr_v6;
	};
	char comm[TASK_COMM_LEN];
	__u64 delta_us;
	__u64 ts_us;
	__u32 tgid;
	int af;
	__u16 dport;
};


#endif /* __TCPCONNLAT_H_ */
