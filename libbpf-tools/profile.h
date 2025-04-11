// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN		16
#define MAX_CPU_NR		128
#define MAX_ENTRIES		10240
#define MAX_PID_NR		30
#define MAX_TID_NR		30
// maximum kernel symbol name length including trailing 0
#define MAX_SYM_LEN		128
#define USDT_PROVIDER		bpfprofiler
#define USDT_READY_TO_CONVERT	ready_to_launch_converter


#define STRINGIFY(x) #x
// Useful to convert usdt tokens to strings
#define TOSTRING(x) STRINGIFY(x)

struct key_t {
	__u32 pid;
	int user_stack_id;
	int kern_stack_id;
	char name[TASK_COMM_LEN];
};

#endif /* __PROFILE_H */
