#ifndef __BITESIZE_H
#define __BITESIZE_H

#define TASK_COMM_LEN	16
#define MAX_SLOTS	20

struct hist_key {
	char comm[TASK_COMM_LEN];
};

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __BITESIZE_H */
