// SPDX-License-Identifier: GPL-2.0
//  Copyright (c) 2025 Samsung Electronics Co., Ltd.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "xfsAG.h"

const volatile __u32 ag_count = 0;
const volatile __u32 device_num = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_AG_CNT);
	__type(key, u32);
	__type(value, ag_infos);
} map_ag_infos SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct file_rwu_key);
	__type(value, enum rwu_type);
} map_file_rwu SEC(".maps");


static __always_inline enum rwu_type get_rwu_type(xfs_ino_t ino_id, long long offset, u64 lenth) {
	struct file_rwu_key rwu_key = { ino_id, offset, lenth };
	enum rwu_type* rwutp = bpf_map_lookup_elem(&map_file_rwu, &rwu_key);
	if (rwutp) {
		return *rwutp;
	}
	return RWU_TYPE_CNT;
}

static __always_inline void delete_rwu_type(xfs_ino_t ino_id, long long offset, u64 lenth) {
	struct file_rwu_key rwu_key = { ino_id, offset, lenth };
	if (bpf_map_delete_elem(&map_file_rwu, &rwu_key))
		bpf_printk("failed to delete map_file_rwu\n");
}

static __always_inline int generic_iomap_deal(u64 agno, enum rwu_type rwut, struct xfs_inode* ip) {
	struct ag_infos* aip;
	u64 id, yu;
	dev_t dev = ip->i_mount->m_super->s_dev;
	if (device_num && dev != device_num)
		return 0;

	aip = bpf_map_lookup_elem(&map_ag_infos, &agno);
	if (!aip) {
		bpf_printk("can't find ag_infos\n");
		return 0;
	}
	__sync_fetch_and_add(&aip->rwu_cnt[rwut], 1);
	return 0;
}
/*******************************************************************************************
********								tracepoint									********	
********************************************************************************************/
/*****									read&write									*****/
SEC("tp_btf/xfs_file_buffered_read")
int BPF_PROG(my_xfs_file_buffered_read, struct kiocb* iocb, struct iov_iter* to) {
	if(!iocb || !to)
                return 0;
	struct file_rwu_key rwu_key = { iocb->ki_filp->f_inode->i_ino, iocb->ki_pos, to->count };
	enum rwu_type rwu_val = RWU_TYPE_BUFFER_READ;

	return bpf_map_update_elem(&map_file_rwu, &rwu_key, &rwu_val, BPF_ANY);
}
SEC("tp_btf/xfs_file_direct_read")
int BPF_PROG(my_xfs_file_direct_read, struct kiocb* iocb, struct iov_iter* to) {
	if(!iocb || !to)
                return 0;
	struct file_rwu_key rwu_key = { iocb->ki_filp->f_inode->i_ino, iocb->ki_pos, to->count };
	enum rwu_type rwu_val = RWU_TYPE_DIRECT_READ;

	return bpf_map_update_elem(&map_file_rwu, &rwu_key, &rwu_val, BPF_ANY);
}
SEC("tp_btf/xfs_file_buffered_write")
int BPF_PROG(my_xfs_file_buffered_write, struct kiocb* iocb, struct iov_iter* from) {
	if(!iocb || !from)
                return 0;
	struct file_rwu_key rwu_key = { iocb->ki_filp->f_inode->i_ino, iocb->ki_pos, from->count };
	enum rwu_type rwu_val = RWU_TYPE_BUFFER_WRITE;

	return bpf_map_update_elem(&map_file_rwu, &rwu_key, &rwu_val, BPF_ANY);
}
SEC("tp_btf/xfs_file_direct_write")
int BPF_PROG(my_xfs_file_direct_write, struct kiocb* iocb, struct iov_iter* from) {
	if(!iocb || !from)
                return 0;
	struct file_rwu_key rwu_key = { iocb->ki_filp->f_inode->i_ino, iocb->ki_pos, from->count };
	enum rwu_type rwu_val = RWU_TYPE_DIRECT_WRITE;

	return bpf_map_update_elem(&map_file_rwu, &rwu_key, &rwu_val, BPF_ANY);
}
SEC("tp_btf/xfs_iomap_alloc")
int BPF_PROG(my_xfs_iomap_alloc, struct xfs_inode* ip, xfs_off_t offset, ssize_t count, int whichfork, struct xfs_bmbt_irec* irec) {
	if(!ip || !irec)
                return 0;
	u64 agno = XFS_FSB_TO_AGNO(ip->i_mount, irec->br_startblock);
	enum rwu_type rwut = get_rwu_type(ip->i_ino, offset, count);

	if (agno >= ag_count || agno < 0) {
		bpf_printk("invalid agno\n");
		goto cleanup;
	}
	if (rwut >= RWU_TYPE_CNT || rwut < RWU_TYPE_BUFFER_READ) {
		bpf_printk("invalid RWU TYPE\n");
		goto cleanup;
	}
	if (generic_iomap_deal(agno, rwut, ip)) {
		goto cleanup;
	}
cleanup:
	delete_rwu_type(ip->i_ino, offset, count);
	return 0;
}
SEC("tp_btf/xfs_iomap_found")
int BPF_PROG(my_xfs_iomap_found, struct xfs_inode* ip, xfs_off_t offset, ssize_t count, int whichfork, struct xfs_bmbt_irec* irec) {
	if(!ip || !irec)
                return 0;
	u64 agno = XFS_FSB_TO_AGNO(ip->i_mount, irec->br_startblock);
	enum rwu_type rwut = get_rwu_type(ip->i_ino, offset, count);

	if (agno >= ag_count || agno < 0) {
		bpf_printk("invalid agno\n");
		goto cleanup;
	}
	if (rwut >= RWU_TYPE_CNT || rwut < RWU_TYPE_BUFFER_READ) {
		bpf_printk("invalid RWU TYPE\n");
		goto cleanup;
	}
	if (rwut == RWU_TYPE_BUFFER_WRITE)
		rwut = RWU_TYPE_BUFFER_UPDATE;
	else if (rwut == RWU_TYPE_DIRECT_WRITE)
		rwut = RWU_TYPE_DIRECT_UPDATE;
	if (generic_iomap_deal(agno, rwut, ip)) {
		goto cleanup;
	}
cleanup:
	delete_rwu_type(ip->i_ino, offset, count);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
