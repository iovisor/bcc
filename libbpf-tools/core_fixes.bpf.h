/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */

#ifndef __CORE_FIXES_BPF_H
#define __CORE_FIXES_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

/**
 * commit 2f064a59a1 ("sched: Change task_struct::state") changes
 * the name of task_struct::state to task_struct::__state
 * see:
 *     https://github.com/torvalds/linux/commit/2f064a59a1
 */
struct task_struct___o {
	volatile long int state;
} __attribute__((preserve_access_index));

struct task_struct___x {
	unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
	struct task_struct___x *t = task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ((struct task_struct___o *)task, state);
}

/**
 * commit 309dca309fc3 ("block: store a block_device pointer in struct bio")
 * adds a new member bi_bdev which is a pointer to struct block_device
 * see:
 *     https://github.com/torvalds/linux/commit/309dca309fc3
 */
struct bio___o {
	struct gendisk *bi_disk;
} __attribute__((preserve_access_index));

struct bio___x {
	struct block_device *bi_bdev;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_gendisk(void *bio)
{
	struct bio___x *b = bio;

	if (bpf_core_field_exists(b->bi_bdev))
		return BPF_CORE_READ(b, bi_bdev, bd_disk);
	return BPF_CORE_READ((struct bio___o *)bio, bi_disk);
}

/**
 * commit d5869fdc189f ("block: introduce block_rq_error tracepoint")
 * adds a new tracepoint block_rq_error and it shares the same arguments
 * with tracepoint block_rq_complete. As a result, the kernel BTF now has
 * a `struct trace_event_raw_block_rq_completion` instead of
 * `struct trace_event_raw_block_rq_complete`.
 * see:
 *     https://github.com/torvalds/linux/commit/d5869fdc189f
 */
struct trace_event_raw_block_rq_complete___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
} __attribute__((preserve_access_index));

struct trace_event_raw_block_rq_completion___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
} __attribute__((preserve_access_index));

static __always_inline bool has_block_rq_completion()
{
	if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
		return true;
	return false;
}

/**
 * commit d152c682f03c ("block: add an explicit ->disk backpointer to the
 * request_queue") and commit f3fa33acca9f ("block: remove the ->rq_disk
 * field in struct request") make some changes to `struct request` and
 * `struct request_queue`. Now, to get the `struct gendisk *` field in a CO-RE
 * way, we need both `struct request` and `struct request_queue`.
 * see:
 *     https://github.com/torvalds/linux/commit/d152c682f03c
 *     https://github.com/torvalds/linux/commit/f3fa33acca9f
 */
struct request_queue___x {
	struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x {
	struct request_queue___x *q;
	struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request)
{
	struct request___x *r = request;

	if (bpf_core_field_exists(r->rq_disk))
		return BPF_CORE_READ(r, rq_disk);
	return BPF_CORE_READ(r, q, disk);
}

/**
 * commit 6521f8917082("namei: prepare for idmapped mounts") add `struct
 * user_namespace *mnt_userns` as vfs_create() and vfs_unlink() first argument.
 * At the same time, struct renamedata {} add `struct user_namespace
 * *old_mnt_userns` item. Now, to kprobe vfs_create()/vfs_unlink() in a CO-RE
 * way, determine whether there is a `old_mnt_userns` field for `struct
 * renamedata` to decide which input parameter of the vfs_create() to use as
 * `dentry`.
 * commit abf08576afe3("fs: port vfs_*() helpers to struct mnt_idmap") use
 * `struct mnt_idmap *new_mnt_idmap` instead of `struct user_namespace *
 * old_mnt_userns`.
 * see:
 *     https://github.com/torvalds/linux/commit/6521f8917082
 *     https://github.com/torvalds/linux/commit/abf08576afe3
 */
struct renamedata___x {
	struct user_namespace *old_mnt_userns;
	struct new_mnt_idmap *new_mnt_idmap;
} __attribute__((preserve_access_index));

static __always_inline bool renamedata_has_old_mnt_userns_field(void)
{
	if (bpf_core_field_exists(struct renamedata___x, old_mnt_userns))
		return true;
	return false;
}

static __always_inline bool renamedata_has_new_mnt_idmap_field(void)
{
	if (bpf_core_field_exists(struct renamedata___x, new_mnt_idmap))
		return true;
	return false;
}

/**
 * commit 3544de8ee6e4("mm, tracing: record slab name for kmem_cache_free()")
 * replaces `trace_event_raw_kmem_free` with `trace_event_raw_kfree` and adds
 * `tracepoint_kmem_cache_free` to enhance the information recorded for
 * `kmem_cache_free`.
 * see:
 *     https://github.com/torvalds/linux/commit/3544de8ee6e4
 */

struct trace_event_raw_kmem_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kfree___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

static __always_inline bool has_kfree()
{
	if (bpf_core_type_exists(struct trace_event_raw_kfree___x))
		return true;
	return false;
}

static __always_inline bool has_kmem_cache_free()
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_cache_free___x))
		return true;
	return false;
}

/**
 * commit 11e9734bcb6a("mm/slab_common: unify NUMA and UMA version of
 * tracepoints") drops kmem_alloc event class, rename kmem_alloc_node to
 * kmem_alloc, so `trace_event_raw_kmem_alloc_node` is not existed any more.
 * see:
 *    https://github.com/torvalds/linux/commit/11e9734bcb6a
 */
struct trace_event_raw_kmem_alloc_node___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

static __always_inline bool has_kmem_alloc_node(void)
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc_node___x))
		return true;
	return false;
}

/**
 * commit 2c1d697fb8ba("mm/slab_common: drop kmem_alloc & avoid dereferencing
 * fields when not using") drops kmem_alloc event class. As a result,
 * `trace_event_raw_kmem_alloc` is removed, `trace_event_raw_kmalloc` and
 * `trace_event_raw_kmem_cache_alloc` are added.
 * see:
 *    https://github.com/torvalds/linux/commit/2c1d697fb8ba
 */
struct trace_event_raw_kmem_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmalloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

static __always_inline bool has_kmem_alloc(void)
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc___x))
		return true;
	return false;
}

/**
 * The bpf_get_socket_cookie helper is landed since kernel v4.12，
 * but only available for tracing programs since kernel v5.12
 * via commit c5dbb89fc2ac("bpf: Expose bpf_get_socket_cookie to tracing programs").
 * Since the helper is used to provide a unique socket identifier,
 * we could use the sock itself as the identifier if the helper is not available.
 * Here, we use BPF_FUNC_check_mtu to check the availability of the helper
 * since they are both introduced in v5.12.
 *
 * see:
 *    https://github.com/torvalds/linux/commit/91b8270f2a4d
 *    https://github.com/torvalds/linux/commit/c5dbb89fc2ac
 *    https://github.com/torvalds/linux/commit/34b2021cc616
 */
static __always_inline __u64 get_sock_ident(struct sock *sk)
{
	if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_check_mtu)) {
		return bpf_get_socket_cookie(sk);
	}
	return (__u64)sk;
}

/**
 * During kernel 6.6 development cycle, several bitfields in struct inet_sock gone,
 * they are placed in inet_sock::inet_flags instead ([0]).
 *
 * References:
 *   [0]: https://lore.kernel.org/all/20230816081547.1272409-1-edumazet@google.com/
 */
struct inet_sock___o {
	__u8 freebind: 1;
	__u8 transparent: 1;
	__u8 bind_address_no_port: 1;
};

enum {
	INET_FLAGS_FREEBIND___x = 11,
	INET_FLAGS_TRANSPARENT___x = 15,
	INET_FLAGS_BIND_ADDRESS_NO_PORT___x = 18,
};

struct inet_sock___x {
	unsigned long inet_flags;
};

static __always_inline __u8 get_inet_sock_freebind(void *inet_sock)
{
	unsigned long inet_flags;

	if (bpf_core_field_exists(struct inet_sock___o, freebind))
		return BPF_CORE_READ_BITFIELD_PROBED((struct inet_sock___o *)inet_sock, freebind);

	inet_flags = BPF_CORE_READ((struct inet_sock___x *)inet_sock, inet_flags);
	return (1 << INET_FLAGS_FREEBIND___x) & inet_flags ? 1 : 0;
}

static __always_inline __u8 get_inet_sock_transparent(void *inet_sock)
{
	unsigned long inet_flags;

	if (bpf_core_field_exists(struct inet_sock___o, transparent))
		return BPF_CORE_READ_BITFIELD_PROBED((struct inet_sock___o *)inet_sock, transparent);

	inet_flags = BPF_CORE_READ((struct inet_sock___x *)inet_sock, inet_flags);
	return (1 << INET_FLAGS_TRANSPARENT___x) & inet_flags ? 1 : 0;
}

static __always_inline __u8 get_inet_sock_bind_address_no_port(void *inet_sock)
{
	unsigned long inet_flags;

	if (bpf_core_field_exists(struct inet_sock___o, bind_address_no_port))
		return BPF_CORE_READ_BITFIELD_PROBED((struct inet_sock___o *)inet_sock, bind_address_no_port);

	inet_flags = BPF_CORE_READ((struct inet_sock___x *)inet_sock, inet_flags);
	return (1 << INET_FLAGS_BIND_ADDRESS_NO_PORT___x) & inet_flags ? 1 : 0;
}

#endif /* __CORE_FIXES_BPF_H */
