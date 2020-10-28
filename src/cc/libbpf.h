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

#include "linux/bpf.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_create_map_attr;
struct bpf_load_program_attr;

enum bpf_probe_attach_type {
	BPF_PROBE_ENTRY,
	BPF_PROBE_RETURN
};

int bcc_create_map(enum bpf_map_type map_type, const char *name,
                   int key_size, int value_size, int max_entries,
                   int map_flags);
int bcc_create_map_xattr(struct bpf_create_map_attr *attr, bool allow_rlimit);
int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags);
int bpf_lookup_elem(int fd, void *key, void *value);
int bpf_delete_elem(int fd, void *key);
int bpf_get_first_key(int fd, void *key, size_t key_size);
int bpf_get_next_key(int fd, void *key, void *next_key);
int bpf_lookup_and_delete(int fd, void *key, void *value);

/*
 * Load a BPF program, and return the FD of the loaded program.
 *
 * On newer Kernels, the parameter name is used to identify the loaded program
 * for inspection and debugging. It could be different from the function name.
 *
 * If log_level has value greater than 0, or the load failed, it will enable
 * extra logging of loaded BPF bytecode and register status, and will print the
 * logging message to stderr. In such cases:
 *   - If log_buf and log_buf_size are provided, it will use and also write the
 *     log messages to the provided log_buf. If log_buf is insufficient in size,
 *     it will not to any additional memory allocation.
 *   - Otherwise, it will allocate an internal temporary buffer for log message
 *     printing, and continue to attempt increase that allocated buffer size if
 *     initial attempt was insufficient in size.
 */
int bcc_prog_load(enum bpf_prog_type prog_type, const char *name,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, unsigned kern_version,
                  int log_level, char *log_buf, unsigned log_buf_size);
int bcc_prog_load_xattr(struct bpf_load_program_attr *attr,
                        int prog_len, char *log_buf,
                        unsigned log_buf_size, bool allow_rlimit);

int bpf_attach_socket(int sockfd, int progfd);

/* create RAW socket. If name is not NULL/a non-empty null-terminated string,
 * bind the raw socket to the interface 'name' */
int bpf_open_raw_sock(const char *name);

typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);
typedef void (*perf_reader_lost_cb)(void *cb_cookie, uint64_t lost);

int bpf_attach_kprobe(int progfd, enum bpf_probe_attach_type attach_type,
                      const char *ev_name, const char *fn_name, uint64_t fn_offset,
                      int maxactive);
int bpf_detach_kprobe(const char *ev_name);

int bpf_attach_uprobe(int progfd, enum bpf_probe_attach_type attach_type,
                      const char *ev_name, const char *binary_path,
                      uint64_t offset, pid_t pid, uint32_t ref_ctr_offset);
int bpf_detach_uprobe(const char *ev_name);

int bpf_attach_tracepoint(int progfd, const char *tp_category,
                          const char *tp_name);
int bpf_detach_tracepoint(const char *tp_category, const char *tp_name);

int bpf_attach_raw_tracepoint(int progfd, const char *tp_name);

int bpf_attach_kfunc(int prog_fd);

int bpf_attach_lsm(int prog_fd);

bool bpf_has_kernel_btf(void);

void * bpf_open_perf_buffer(perf_reader_raw_cb raw_cb,
                            perf_reader_lost_cb lost_cb, void *cb_cookie,
                            int pid, int cpu, int page_cnt);

/* attached a prog expressed by progfd to the device specified in dev_name */
int bpf_attach_xdp(const char *dev_name, int progfd, uint32_t flags);

// attach a prog expressed by progfd to run on a specific perf event. The perf
// event will be created using the perf_event_attr pointer provided.
int bpf_attach_perf_event_raw(int progfd, void *perf_event_attr, pid_t pid,
                              int cpu, int group_fd, unsigned long extra_flags);
// attach a prog expressed by progfd to run on a specific perf event, with
// certain sample period or sample frequency
int bpf_attach_perf_event(int progfd, uint32_t ev_type, uint32_t ev_config,
                          uint64_t sample_period, uint64_t sample_freq,
                          pid_t pid, int cpu, int group_fd);

int bpf_open_perf_event(uint32_t type, uint64_t config, int pid, int cpu);

int bpf_close_perf_event_fd(int fd);

typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

struct ring_buffer;

void * bpf_new_ringbuf(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx);
void bpf_free_ringbuf(struct ring_buffer *rb);
int bpf_add_ringbuf(struct ring_buffer *rb, int map_fd,
                    ring_buffer_sample_fn sample_cb, void *ctx);
int bpf_poll_ringbuf(struct ring_buffer *rb, int timeout_ms);
int bpf_consume_ringbuf(struct ring_buffer *rb);

int bpf_obj_pin(int fd, const char *pathname);
int bpf_obj_get(const char *pathname);
int bpf_obj_get_info(int prog_map_fd, void *info, uint32_t *info_len);
int bpf_prog_compute_tag(const struct bpf_insn *insns, int prog_len,
                         unsigned long long *tag);
int bpf_prog_get_tag(int fd, unsigned long long *tag);
int bpf_prog_get_next_id(uint32_t start_id, uint32_t *next_id);
int bpf_prog_get_fd_by_id(uint32_t id);
int bpf_map_get_fd_by_id(uint32_t id);
int bpf_obj_get_info_by_fd(int prog_fd, void *info, uint32_t *info_len);

int bcc_iter_attach(int prog_fd, union bpf_iter_link_info *link_info,
                    uint32_t link_info_len);
int bcc_iter_create(int link_fd);

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
