// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2025 Samsung Electronics Co., Ltd.
#ifndef __XFSAG_H
#define __XFSAG_H

#define XFS_SUPER_MAGIC 0x58465342      //you can find it in the source code:include/uapi/linux/magic.h
#define MAX_AG_CNT 256

#define	XFS_FSB_TO_AGNO(mp,fsbno)	\
	((xfs_agnumber_t)((fsbno) >> (mp)->m_sb.sb_agblklog))


struct xfs_config{
	unsigned int block_size;
	unsigned int sector_size;
	unsigned int inode_size;
	unsigned int ag_blocks;
	unsigned int data_blocks;
	unsigned int ag_count;
	unsigned long long system_up;
};

enum rwu_type {
	RWU_TYPE_BUFFER_READ,
	RWU_TYPE_DIRECT_READ,
	RWU_TYPE_BUFFER_WRITE,
	RWU_TYPE_DIRECT_WRITE,
	RWU_TYPE_BUFFER_UPDATE,
	RWU_TYPE_DIRECT_UPDATE,
	RWU_TYPE_CNT
};

typedef struct ag_infos {
	__u64 ag_size;
	__u64 rwu_cnt[RWU_TYPE_CNT];
}ag_infos;

typedef struct file_rwu_key {
	__u64 ino_id;
	__s64 offset;
	__u64 lenth;
}file_rwu_key;

#endif
