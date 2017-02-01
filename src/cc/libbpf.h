/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* eBPF mini library */

#ifndef LIBBPF_H
#define LIBBPF_H

#include "compat/linux/bpf.h"

#ifdef __cplusplus
extern "C" {
#endif

enum bpf_probe_attach_type {
	BPF_PROBE_ENTRY,
	BPF_PROBE_RETURN
};

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries, int map_flags);
int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags);
int bpf_lookup_elem(int fd, void *key, void *value);
int bpf_delete_elem(int fd, void *key);
int bpf_get_next_key(int fd, void *key, void *next_key);

int bpf_prog_load(enum bpf_prog_type prog_type,
		  const struct bpf_insn *insns, int insn_len,
		  const char *license, unsigned kern_version,
		  char *log_buf, unsigned log_buf_size);
int bpf_attach_socket(int sockfd, int progfd);

/* create RAW socket and bind to interface 'name' */
int bpf_open_raw_sock(const char *name);

typedef void (*perf_reader_cb)(void *cb_cookie, int pid, uint64_t callchain_num,
                               void *callchain);
typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);

void * bpf_attach_kprobe(int progfd, enum bpf_probe_attach_type attach_type, 
                        const char *ev_name, const char *fn_name,
                        pid_t pid, int cpu, int group_fd,
                        perf_reader_cb cb, void *cb_cookie);

int bpf_detach_kprobe(const char *ev_name);

void * bpf_attach_uprobe(int progfd, enum bpf_probe_attach_type attach_type,
                        const char *ev_name, const char *binary_path, uint64_t offset,
                        pid_t pid, int cpu, int group_fd,
                        perf_reader_cb cb, void *cb_cookie);

int bpf_detach_uprobe(const char *ev_name);

void * bpf_attach_tracepoint(int progfd, const char *tp_category,
                             const char *tp_name, int pid, int cpu,
                             int group_fd, perf_reader_cb cb, void *cb_cookie);
int bpf_detach_tracepoint(const char *tp_category, const char *tp_name);

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb, void *cb_cookie, int pid, int cpu);

/* attached a prog expressed by progfd to the device specified in dev_name */
int bpf_attach_xdp(const char *dev_name, int progfd);

// attach a prog expressed by progfd to run on a specific perf event, with
// certain sample period or sample frequency
int bpf_attach_perf_event(int progfd, uint32_t ev_type, uint32_t ev_config,
                          uint64_t sample_period, uint64_t sample_freq,
                          pid_t pid, int cpu, int group_fd);
int bpf_detach_perf_event(uint32_t ev_type, uint32_t ev_config);

int bpf_obj_pin(int fd, const char *pathname);
int bpf_obj_get(const char *pathname);

#define LOG_BUF_SIZE 65536

// Put non-static/inline functions in their own section with this prefix +
// fn_name to enable discovery by the bcc library.
#define BPF_FN_PREFIX ".bpf.fn."

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

#define BPF_PSEUDO_MAP_FD	1

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#ifdef __cplusplus
}
#endif

#endif
