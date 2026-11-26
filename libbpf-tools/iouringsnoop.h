/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __IOURINGSNOOP_H
#define __IOURINGSNOOP_H

#define TASK_COMM_LEN	16

/*
 * iouringsnoop event structure.
 *
 * Emitted once per io_uring request completion.
 * The key fields are:
 *   delta_us  - submission-to-completion latency in microseconds
 *   ctx       - io_ring_ctx pointer (ring identity / filter handle)
 *   req       - io_kiocb pointer (unique request identity)
 *   pid       - process ID of the submitting task
 *   res       - completion result (negative == error)
 *   opcode    - IORING_OP_* opcode
 *   comm      - process name of the submitting task
 */
struct event {
	__u64 delta_us;   /* latency: complete_ts - submit_ts, in µs   */
	__u64 ctx;        /* io_ring_ctx * cast to u64                  */
	__u64 req;        /* io_kiocb   * cast to u64 (for correlation) */
	__u32 pid;        /* PID of submitting task                     */
	__s32 res;        /* CQE result (< 0 → error)                   */
	__u8  opcode;     /* IORING_OP_* opcode                         */
	char  comm[TASK_COMM_LEN];
};

#endif /* __IOURINGSNOOP_H */
