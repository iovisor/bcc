// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2025 Samsung Electronics Co., Ltd.
#ifndef __EXT4FILE_H
#define __EXT4FILE_H

#define flag(num) (1ULL << num)
#define IOCB_DIRECT		(1 << 17)

enum ts_type {
    TS_TYPE_CREATE,            //time the file is created
    TS_TYPE_MODIFY,            //time the file is newly modified
    TS_TYPE_ACCESS,            //time the file is newly accessed
    TS_TYPE_DELETE,            //time the file is deleted
    TS_TYPE_CNT,
};

enum rw_type {
    RW_TYPE_BUFFER_READ,
    RW_TYPE_DIRECT_READ,
    RW_TYPE_BUFFER_WRITE,
    RW_TYPE_DIRECT_WRITE,
    RW_TYPE_CNT
};

enum file_type {
    FILE_TYPE_REG,             //normal file
    FILE_TYPE_DIR,             //directory
    FILE_TYPE_LINK,            //link
    FILE_TYPE_SYMLINK,         //symlink
    FILE_TYPE_NOD,             //others(like socket, pipe, device file)
    FILE_TYPE_CNT              //nums of file_type
};

struct file_info_key{
    __u32 fk_ino;
    __u32 fk_pa_ino;
    char fk_name[48];
};

struct file_info_val {
    long long fv_size;
    int fv_update_cnt;
    int fv_access_cnt;
    __u64 fv_rw_cnt[RW_TYPE_CNT];
    __u64 fv_ts[TS_TYPE_CNT];
    int fv_hint;
};

struct file_bg_key {
    struct file_info_key bgk_fik;
    int bgk_index;
};

struct bg_info {
    unsigned long bg_id;
    int bg_file_cnt;
    int bg_write_cnt;
    int bg_read_cnt;
    int bg_update_cnt;
    int bg_access_cnt;
};

struct unique_file {
    int ino;
    char filename[48];
};

struct ext4_config {
	uint32_t blocks_per_group;
	uint32_t blocks_count;
	uint32_t bg_cnt;
};

#endif
