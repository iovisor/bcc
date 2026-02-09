// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2026 Samsung Electronics Co., Ltd.
#ifndef __EXT4FILE_H
#define __EXT4FILE_H

#define IOCB_DIRECT		(1 << 17)

#define FD_STDOUT -1
#define FD_STDERR -2

#define NAME_MAX 255

enum rw_type {
    RW_TYPE_BUFFER_READ,
    RW_TYPE_DIRECT_READ,
    RW_TYPE_BUFFER_WRITE,
    RW_TYPE_DIRECT_WRITE,
    RW_TYPE_CNT
};

struct file_info_key{
    __u32 fk_ino;
    __u32 fk_pa_ino;
    char fk_name[NAME_MAX];
};

struct file_info_val {
    __u64 fv_rw_cnt[RW_TYPE_CNT];
    int fv_hint;
    bool fv_delete;
};

struct unique_file {
    int ino;
    char filename[NAME_MAX];
};

struct ext4_config {
	uint32_t blocks_per_group;
	uint32_t blocks_count;
	uint32_t bg_cnt;
};

#endif
