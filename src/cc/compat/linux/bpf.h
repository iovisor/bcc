/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_H__

#include <linux/types.h>
#include "bpf_common.h"

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word (64-bit) */
#define BPF_XADD	0xc0	/* exclusive add */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0    /* LT is unsigned, '<' */
#define BPF_JLE		0xb0    /* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0    /* SLT is signed, '<' */
#define BPF_JSLE	0xd0    /* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
	__u8	data[0];	/* Arbitrary size */
};

/* BPF syscall commands, see bpf(2) man-page for details. */
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER,
	BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE,
	__MAX_BPF_ATTACH_TYPE
};

#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE

/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
#define BPF_F_ALLOW_OVERRIDE	(1U << 0)
#define BPF_F_ALLOW_MULTI	(1U << 1)

/* If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
 * verifier will perform strict alignment checking as if the kernel
 * has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
 * and NET_IP_ALIGN defined to 2.
 */
#define BPF_F_STRICT_ALIGNMENT	(1U << 0)

/* when bpf_ldimm64->src_reg == BPF_PSEUDO_MAP_FD, bpf_ldimm64->imm == fd */
#define BPF_PSEUDO_MAP_FD	1

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL		1

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY		0 /* create new element or update existing */
#define BPF_NOEXIST	1 /* create new element if it didn't exist */
#define BPF_EXIST	2 /* update existing element */

/* flags for BPF_MAP_CREATE command */
#define BPF_F_NO_PREALLOC	(1U << 0)
/* Instead of having one common LRU list in the
 * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
 * which can scale and perform better.
 * Note, the LRU nodes (including free nodes) cannot be moved
 * across different LRU lists.
 */
#define BPF_F_NO_COMMON_LRU	(1U << 1)
/* Specify numa node during map creation */
#define BPF_F_NUMA_NODE		(1U << 2)

/* flags for BPF_PROG_QUERY */
#define BPF_F_QUERY_EFFECTIVE  (1U << 0)

#define BPF_OBJ_NAME_LEN 16U

/* Flags for accessing BPF object */
#define BPF_F_RDONLY           (1U << 3)
#define BPF_F_WRONLY           (1U << 4)

union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
		__u32	map_type;	/* one of enum bpf_map_type */
		__u32	key_size;	/* size of key in bytes */
		__u32	value_size;	/* size of value in bytes */
		__u32	max_entries;	/* max number of entries in a map */
		__u32	map_flags;	/* BPF_MAP_CREATE related
					 * flags defined above.
					 */
		__u32	inner_map_fd;	/* fd pointing to the inner map */
		__u32	numa_node;	/* numa node (effective only if
					 * BPF_F_NUMA_NODE is set).
					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		__u32	map_ifindex;	/* ifindex of netdev to create on */
	};

	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
		__u32		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		__u64		flags;
	};

	struct { /* anonymous struct used by BPF_PROG_LOAD command */
		__u32		prog_type;	/* one of enum bpf_prog_type */
		__u32		insn_cnt;
		__aligned_u64	insns;
		__aligned_u64	license;
		__u32		log_level;	/* verbosity level of verifier */
		__u32		log_size;	/* size of user buffer */
		__aligned_u64	log_buf;	/* user supplied buffer */
		__u32		kern_version;	/* checked when prog_type=kprobe */
		__u32		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
		__u32		prog_ifindex;    /* ifindex of netdev to prep for */
	};

	struct { /* anonymous struct used by BPF_OBJ_* commands */
		__aligned_u64	pathname;
		__u32		bpf_fd;
		__u32		file_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
		__u32		target_fd;	/* container object to attach to */
		__u32		attach_bpf_fd;	/* eBPF program to attach */
		__u32		attach_type;
		__u32		attach_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_TEST_RUN command */
		__u32		prog_fd;
		__u32		retval;
		__u32		data_size_in;
		__u32		data_size_out;
		__aligned_u64	data_in;
		__aligned_u64	data_out;
		__u32		repeat;
		__u32		duration;
	} test;

	struct { /* anonymous struct used by BPF_*_GET_*_ID */
		union {
			__u32		start_id;
			__u32		prog_id;
			__u32		map_id;
		};
		__u32		next_id;
		__u32		open_flags;
	};

	struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
		__u32		bpf_fd;
		__u32		info_len;
		__aligned_u64	info;
	} info;

        struct { /* anonymous struct used by BPF_PROG_QUERY command */
		__u32           target_fd;      /* container object to query */
		__u32           attach_type;
		__u32           query_flags;
		__u32           attach_flags;
		__aligned_u64   prog_ids;
		__u32           prog_cnt;
        } query;
} __attribute__((aligned(8)));

/* BPF helper function descriptions:
 *
 * void *bpf_map_lookup_elem(&map, &key)
 *     Return: Map value or NULL
 *
 * int bpf_map_update_elem(&map, &key, &value, flags)
 *     Return: 0 on success or negative error
 *
 * int bpf_map_delete_elem(&map, &key)
 *     Return: 0 on success or negative error
 *
 * int bpf_probe_read(void *dst, int size, const void *src)
 *     Return: 0 on success or negative error
 *
 * u64 bpf_ktime_get_ns(void)
 *     Return: current ktime
 *
 * int bpf_trace_printk(const char *fmt, int fmt_size, ...)
 *     Return: length of buffer written or negative error
 *
 * u32 bpf_prandom_u32(void)
 *     Return: random value
 *
 * u32 bpf_raw_smp_processor_id(void)
 *     Return: SMP processor ID
 *
 * int bpf_skb_store_bytes(skb, offset, from, len, flags)
 *     store bytes into packet
 *     @skb: pointer to skb
 *     @offset: offset within packet from skb->mac_header
 *     @from: pointer where to copy bytes from
 *     @len: number of bytes to store into packet
 *     @flags: bit 0 - if true, recompute skb->csum
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_l3_csum_replace(skb, offset, from, to, flags)
 *     recompute IP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where IP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_l4_csum_replace(skb, offset, from, to, flags)
 *     recompute TCP/UDP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where TCP/UDP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             bit 4 - is pseudo header
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_tail_call(ctx, prog_array_map, index)
 *     jump into another BPF program
 *     @ctx: context pointer passed to next program
 *     @prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
 *     @index: 32-bit index inside array that selects specific program to run
 *     Return: 0 on success or negative error
 *
 * int bpf_clone_redirect(skb, ifindex, flags)
 *     redirect to another netdev
 *     @skb: pointer to skb
 *     @ifindex: ifindex of the net device
 *     @flags: bit 0 - if set, redirect to ingress instead of egress
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * u64 bpf_get_current_pid_tgid(void)
 *     Return: current->tgid << 32 | current->pid
 *
 * u64 bpf_get_current_uid_gid(void)
 *     Return: current_gid << 32 | current_uid
 *
 * int bpf_get_current_comm(char *buf, int size_of_buf)
 *     stores current->comm into buf
 *     Return: 0 on success or negative error
 *
 * u32 bpf_get_cgroup_classid(skb)
 *     retrieve a proc's classid
 *     @skb: pointer to skb
 *     Return: classid if != 0
 *
 * int bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_vlan_pop(skb)
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_get_tunnel_key(skb, key, size, flags)
 * int bpf_skb_set_tunnel_key(skb, key, size, flags)
 *     retrieve or populate tunnel metadata
 *     @skb: pointer to skb
 *     @key: pointer to 'struct bpf_tunnel_key'
 *     @size: size of 'struct bpf_tunnel_key'
 *     @flags: room for future extensions
 *     Return: 0 on success or negative error
 *
 * u64 bpf_perf_event_read(map, flags)
 *     read perf event counter value
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     Return: value of perf event counter read or error code
 *
 * int bpf_redirect(ifindex, flags)
 *     redirect to another netdev
 *     @ifindex: ifindex of the net device
 *     @flags:
 *       cls_bpf:
 *          bit 0 - if set, redirect to ingress instead of egress
 *          other bits - reserved
 *       xdp_bpf:
 *         all bits - reserved
 *     Return: cls_bpf: TC_ACT_REDIRECT on success or TC_ACT_SHOT on error
 *            xdp_bfp: XDP_REDIRECT on success or XDP_ABORT on error
 *
 * int bpf_redirect_map(map, key, flags)
 *     redirect to endpoint in map
 *     @map: pointer to dev map
 *     @key: index in map to lookup
 *     @flags: --
 *     Return: XDP_REDIRECT on success or XDP_ABORT on error
 *
 * u32 bpf_get_route_realm(skb)
 *     retrieve a dst's tclassid
 *     @skb: pointer to skb
 *     Return: realm if != 0
 *
 * int bpf_perf_event_output(ctx, map, flags, data, size)
 *     output perf raw sample
 *     @ctx: struct pt_regs*
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @data: data on stack to be output as raw data
 *     @size: size of data
 *     Return: 0 on success or negative error
 *
 * int bpf_get_stackid(ctx, map, flags)
 *     walk user or kernel stack and return id
 *     @ctx: struct pt_regs*
 *     @map: pointer to stack_trace map
 *     @flags: bits 0-7 - numer of stack frames to skip
 *             bit 8 - collect user stack instead of kernel
 *             bit 9 - compare stacks by hash only
 *             bit 10 - if two different stacks hash into the same stackid
 *                      discard old
 *             other bits - reserved
 *     Return: >= 0 stackid on success or negative error
 *
 * s64 bpf_csum_diff(from, from_size, to, to_size, seed)
 *     calculate csum diff
 *     @from: raw from buffer
 *     @from_size: length of from buffer
 *     @to: raw to buffer
 *     @to_size: length of to buffer
 *     @seed: optional seed
 *     Return: csum result or negative error code
 *
 * int bpf_skb_get_tunnel_opt(skb, opt, size)
 *     retrieve tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: option size
 *
 * int bpf_skb_set_tunnel_opt(skb, opt, size)
 *     populate tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_change_proto(skb, proto, flags)
 *     Change protocol of the skb. Currently supported is v4 -> v6,
 *     v6 -> v4 transitions. The helper will also resize the skb. eBPF
 *     program is expected to fill the new headers via skb_store_bytes
 *     and lX_csum_replace.
 *     @skb: pointer to skb
 *     @proto: new skb->protocol type
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_change_type(skb, type)
 *     Change packet type of skb.
 *     @skb: pointer to skb
 *     @type: new skb->pkt_type type
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_under_cgroup(skb, map, index)
 *     Check cgroup2 membership of skb
 *     @skb: pointer to skb
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 skb failed the cgroup2 descendant test
 *       == 1 skb succeeded the cgroup2 descendant test
 *        < 0 error
 *
 * u32 bpf_get_hash_recalc(skb)
 *     Retrieve and possibly recalculate skb->hash.
 *     @skb: pointer to skb
 *     Return: hash
 *
 * u64 bpf_get_current_task(void)
 *     Returns current task_struct
 *     Return: current
 *
 * int bpf_probe_write_user(void *dst, void *src, int len)
 *     safely attempt to write to a location
 *     @dst: destination address in userspace
 *     @src: source address on stack
 *     @len: number of bytes to copy
 *     Return: 0 on success or negative error
 *
 * int bpf_current_task_under_cgroup(map, index)
 *     Check cgroup2 membership of current task
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 current failed the cgroup2 descendant test
 *       == 1 current succeeded the cgroup2 descendant test
 *        < 0 error
 *
 * int bpf_skb_change_tail(skb, len, flags)
 *     The helper will resize the skb to the given new size, to be used f.e.
 *     with control messages.
 *     @skb: pointer to skb
 *     @len: new skb length
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_pull_data(skb, len)
 *     The helper will pull in non-linear data in case the skb is non-linear
 *     and not all of len are part of the linear section. Only needed for
 *     read/write with direct packet access.
 *     @skb: pointer to skb
 *     @len: len to make read/writeable
 *     Return: 0 on success or negative error
 *
 * s64 bpf_csum_update(skb, csum)
 *     Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
 *     @skb: pointer to skb
 *     @csum: csum to add
 *     Return: csum on success or negative error
 *
 * void bpf_set_hash_invalid(skb)
 *     Invalidate current skb->hash.
 *     @skb: pointer to skb
 *
 * int bpf_get_numa_node_id()
 *     Return: Id of current NUMA node.
 *
 * int bpf_skb_change_head()
 *     Grows headroom of skb and adjusts MAC header offset accordingly.
 *     Will extends/reallocae as required automatically.
 *     May change skb data pointer and will thus invalidate any check
 *     performed for direct packet access.
 *     @skb: pointer to skb
 *     @len: length of header to be pushed in front
 *     @flags: Flags (unused for now)
 *     Return: 0 on success or negative error
 *
 * int bpf_xdp_adjust_head(xdp_md, delta)
 *     Adjust the xdp_md.data by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data
 *     Return: 0 on success or negative on error
 *
 * int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
 *     Copy a NUL terminated string from unsafe address. In case the string
 *     length is smaller than size, the target is not padded with further NUL
 *     bytes. In case the string length is larger than size, just count-1
 *     bytes are copied and the last byte is set to NUL.
 *     @dst: destination address
 *     @size: maximum number of bytes to copy, including the trailing NUL
 *     @unsafe_ptr: unsafe address
 *     Return:
 *       > 0 length of the string including the trailing NUL on success
 *       < 0 error
 *
 * u64 bpf_get_socket_cookie(skb)
 *     Get the cookie for the socket stored inside sk_buff.
 *     @skb: pointer to skb
 *     Return: 8 Bytes non-decreasing number on success or 0 if the socket
 *     field is missing inside sk_buff
 *
 * u32 bpf_get_socket_uid(skb)
 *     Get the owner uid of the socket stored inside sk_buff.
 *     @skb: pointer to skb
 *     Return: uid of the socket owner on success or overflowuid if failed.
 *
 * u32 bpf_set_hash(skb, hash)
 *     Set full skb->hash.
 *     @skb: pointer to skb
 *     @hash: hash to set
 *
 * int bpf_setsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls setsockopt. Not all opts are available, only those with
 *     integer optvals plus TCP_CONGESTION.
 *     Supported levels: SOL_SOCKET and IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: SOL_SOCKET or IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_getsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls getsockopt. Not all opts are available.
 *     Supported levels: IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_skb_adjust_room(skb, len_diff, mode, flags)
 *     Grow or shrink room in sk_buff.
 *     @skb: pointer to skb
 *     @len_diff: (signed) amount of room to grow/shrink
 *     @mode: operation mode (enum bpf_adj_room_mode)
 *     @flags: reserved for future use
 *     Return: 0 on success or negative error code
 *
 * int bpf_sk_redirect_map(map, key, flags)
 *     Redirect skb to a sock in map using key as a lookup key for the
 *     sock in map.
 *     @map: pointer to sockmap
 *     @key: key to lookup sock in map
 *     @flags: reserved for future use
 *     Return: SK_PASS
 *
 * int bpf_sock_map_update(skops, map, key, flags)
 *     @skops: pointer to bpf_sock_ops
 *     @map: pointer to sockmap to update
 *     @key: key to insert/update sock in map
 *     @flags: same flags as map update elem
 *
 * int bpf_xdp_adjust_meta(xdp_md, delta)
 *     Adjust the xdp_md.data_meta by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data_meta
 *     Return: 0 on success or negative on error
 *
 * int bpf_perf_event_read_value(map, flags, buf, buf_size)
 *     read perf event counter value and perf event enabled/running time
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return: 0 on success or negative error code
 *
 * int bpf_perf_prog_read_value(ctx, buf, buf_size)
 *     read perf prog attached perf event counter and enabled/running time
 *     @ctx: pointer to ctx
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return : 0 on success or negative error code
 *
 * int bpf_override_return(pt_regs, rc)
 *     @pt_regs: pointer to struct pt_regs
 *     @rc: the return value to set
 */
#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
	__BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN

/* All flags used by eBPF helper functions, placed here. */

/* BPF_FUNC_skb_store_bytes flags. */
#define BPF_F_RECOMPUTE_CSUM		(1ULL << 0)
#define BPF_F_INVALIDATE_HASH		(1ULL << 1)

/* BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
 * First 4 bits are for passing the header field size.
 */
#define BPF_F_HDR_FIELD_MASK		0xfULL

/* BPF_FUNC_l4_csum_replace flags. */
#define BPF_F_PSEUDO_HDR		(1ULL << 4)
#define BPF_F_MARK_MANGLED_0		(1ULL << 5)
#define BPF_F_MARK_ENFORCE		(1ULL << 6)

/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
#define BPF_F_INGRESS			(1ULL << 0)

/* BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags. */
#define BPF_F_TUNINFO_IPV6		(1ULL << 0)

/* BPF_FUNC_get_stackid flags. */
#define BPF_F_SKIP_FIELD_MASK		0xffULL
#define BPF_F_USER_STACK		(1ULL << 8)
#define BPF_F_FAST_STACK_CMP		(1ULL << 9)
#define BPF_F_REUSE_STACKID		(1ULL << 10)

/* BPF_FUNC_skb_set_tunnel_key flags. */
#define BPF_F_ZERO_CSUM_TX		(1ULL << 1)
#define BPF_F_DONT_FRAGMENT		(1ULL << 2)

/* BPF_FUNC_perf_event_output and BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK
/* BPF_FUNC_perf_event_output for sk_buff input context. */
#define BPF_F_CTXLEN_MASK		(0xfffffULL << 32)

/* Mode for BPF_FUNC_skb_adjust_room helper. */
enum bpf_adj_room_mode {
	BPF_ADJ_ROOM_NET,
};

/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	__u32 family;
	__u32 remote_ip4;       /* Stored in network byte order */
	__u32 local_ip4;        /* Stored in network byte order */
	__u32 remote_ip6[4];    /* Stored in network byte order */
	__u32 local_ip6[4];     /* Stored in network byte order */
	__u32 remote_port;      /* Stored in network byte order */
	__u32 local_port;       /* stored in host byte order */
	/* ... here. */

	__u32 data_meta;
};

struct bpf_tunnel_key {
	__u32 tunnel_id;
	union {
		__u32 remote_ipv4;
		__u32 remote_ipv6[4];
	};
	__u8 tunnel_tos;
	__u8 tunnel_ttl;
	__u16 tunnel_ext;
	__u32 tunnel_label;
};

/* Generic BPF return codes which all BPF program types may support.
 * The values are binary compatible with their TC_ACT_* counter-part to
 * provide backwards compatibility with existing SCHED_CLS and SCHED_ACT
 * programs.
 *
 * XDP is handled seprately, see XDP_*.
 */
enum bpf_ret_code {
	BPF_OK = 0,
	/* 1 reserved */
	BPF_DROP = 2,
	/* 3-6 reserved */
	BPF_REDIRECT = 7,
	/* >127 are reserved for prog type specific return codes */
};

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
};

#define XDP_PACKET_HEADROOM 256

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 */
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS,
};

#define BPF_TAG_SIZE	8

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8  tag[BPF_TAG_SIZE];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__aligned_u64 jited_prog_insns;
	__aligned_u64 xlated_prog_insns;
	__u64 load_time;        /* ns since boottime */
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__aligned_u64 map_ids;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u64 netns_dev;
	__u64 netns_ino;
} __attribute__((aligned(8)));

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u64 netns_dev;
	__u64 netns_ino;
} __attribute__((aligned(8)));

/* User bpf_sock_ops struct to access socket values and specify request ops
 * and their replies.
 * Some of this fields are in network (bigendian) byte order and may need
 * to be converted before use (bpf_ntohl() defined in samples/bpf/bpf_endian.h).
 * New fields can only be added at the end of this structure
 */
struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	__u32 is_fullsock;	/* Some TCP fields are only valid if
				 * there is a full socket. If not, the
				 * fields read as zero.
				 */
	__u32 snd_cwnd;
	__u32 srtt_us;		/* Averaged RTT << 3 in usecs */
};

/* List of known BPF sock_ops operators.
 * New entries can only be added at the end
 */
enum {
	BPF_SOCK_OPS_VOID,
	BPF_SOCK_OPS_TIMEOUT_INIT,	/* Should return SYN-RTO value to use or
					 * -1 if default value should be used
					 */
	BPF_SOCK_OPS_RWND_INIT,		/* Should return initial advertized
					 * window (in packets) or -1 if default
					 * value should be used
					 */
	BPF_SOCK_OPS_TCP_CONNECT_CB,	/* Calls BPF program right before an
					 * active connection is initialized
					 */
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,	/* Calls BPF program when an
						 * active connection is
						 * established
						 */
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,	/* Calls BPF program when a
						 * passive connection is
						 * established
						 */
	BPF_SOCK_OPS_NEEDS_ECN,		/* If connection's congestion control
					 * needs ECN
					 */
	BPF_SOCK_OPS_BASE_RTT,		/* Get base RTT. The correct value is
					 * based on the path and may be
					 * dependent on the congestion control
					 * algorithm. In general it indicates
					 * a congestion threshold. RTTs above
					 * this indicate congestion
					 */
};

#define TCP_BPF_IW		1001	/* Set TCP initial congestion window */
#define TCP_BPF_SNDCWND_CLAMP	1002	/* Set sndcwnd_clamp */

struct bpf_perf_event_value {
	__u64 counter;
	__u64 enabled;
	__u64 running;
};

#define BPF_DEVCG_ACC_MKNOD    (1ULL << 0)
#define BPF_DEVCG_ACC_READ     (1ULL << 1)
#define BPF_DEVCG_ACC_WRITE    (1ULL << 2)

#define BPF_DEVCG_DEV_BLOCK    (1ULL << 0)
#define BPF_DEVCG_DEV_CHAR     (1ULL << 1)

struct bpf_cgroup_dev_ctx {
	/* access_type encoded as (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_* */
	__u32 access_type;
	__u32 major;
	__u32 minor;
};

#endif /* _UAPI__LINUX_BPF_H__ */
