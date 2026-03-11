// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2026 Samsung Electronics Co., Ltd.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ext4file.h"

volatile __u64 dev_target = 0;
volatile __u64 blocks_per_group = 0;

#define N 16
#define GROUP 64

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000000);
	__type(key, u32);
	__type(value, struct file_info_key);
} ino_name_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000000);
	__type(key, struct file_info_key);
	__type(value, struct file_info_val);
} file_info_map SEC(".maps");

static __always_inline bool str_equal(const char *a, const char *b) {
    for (size_t i = 0; i < MAX_FILE_NAME; i++) {
        if (a[i] == '\0' && b[i] == '\0')
            return true;
        if (a[i] != b[i])
            return false;
    }
    return true;
}

SEC("fexit/ext4_add_entry")
int BPF_PROG(my_ext4_add_entry, handle_t *handle,
    struct dentry *dentry, struct inode *inode)
{
    struct inode *pa_inode = dentry->d_parent->d_inode;
    dev_t dev_cur = pa_inode->i_sb->s_dev;
    u64 ino_id = inode->i_ino;
    struct file_info_key fik = {};
    struct file_info_val fiv = {};

    if (dev_target && dev_target != dev_cur)
        return 0;

    fik.fk_ino = ino_id;
    fik.fk_pa_ino = pa_inode->i_ino;
    bpf_probe_read_str(&fik.fk_name,
        sizeof(fik.fk_name), dentry->d_name.name);

    if (bpf_map_update_elem(&file_info_map, &fik, &fiv, BPF_ANY))
        return 0;
    if (bpf_map_update_elem(&ino_name_map, &ino_id, &fik, BPF_ANY))
        return 0;
    return 0;
}

SEC("tp_btf/ext4_unlink_enter")
int BPF_PROG(my_ext4_unlink, 
    struct inode *pa_inode, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    struct file_info_key fik = {}, *fikp;
    struct file_info_val *fivp = NULL;
    u64 ino_id = inode->i_ino;
    dev_t dev_cur = pa_inode->i_sb->s_dev;
    if (dev_target && dev_target != dev_cur)
        return 0;
    
    fik.fk_ino = inode->i_ino;
    fik.fk_pa_ino = pa_inode->i_ino;
    bpf_probe_read_str(&fik.fk_name,
        sizeof(fik.fk_name), dentry->d_name.name);
    fivp = bpf_map_lookup_elem(&file_info_map, &fik);
    if (!fivp)
        return 0;
    fivp->fv_delete = true;
	fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp)
        return 0;
    if (str_equal(fikp->fk_name, fik.fk_name))
        bpf_map_delete_elem(&ino_name_map, &ino_id);
    return 0;
}

SEC("fentry/ext4_rmdir")
int BPF_PROG(my_ext4_rmdir,
    struct inode *dir, struct dentry *dentry) 
{
    struct inode *inode = dentry->d_inode;
    struct file_info_key fik = {}, *fikp;
    struct file_info_val *fivp = NULL;
    u64 ino_id = inode->i_ino;
    dev_t dev_cur = inode->i_sb->s_dev;
    if (dev_target && dev_target != dev_cur)
        return 0;
    
    fik.fk_ino = inode->i_ino;
    fik.fk_pa_ino = dir->i_ino;
    bpf_probe_read_str(&fik.fk_name,
        sizeof(fik.fk_name), dentry->d_name.name);
    fivp = bpf_map_lookup_elem(&file_info_map, &fik);
    if (!fivp)
        return 0;
    fivp->fv_delete = true;

    fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp)
        return 0;
    if (str_equal(fikp->fk_name, fik.fk_name))
        bpf_map_delete_elem(&ino_name_map, &ino_id);
    return 0;
}

SEC("fentry/ext4_file_write_iter")
int BPF_PROG(my_ext4_file_write_iter, 
    struct kiocb *iocb, struct iov_iter *from)
{
    struct inode *inode = iocb->ki_filp->f_inode;
    dev_t dev_cur = inode->i_sb->s_dev;
    struct file_info_key *fikp = NULL;
    struct file_info_val *fivp = NULL;
    u64 ino_id = inode->i_ino;

    if (dev_target && dev_target != dev_cur)
        return 0;

    fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp)
        return 0;
    fivp = bpf_map_lookup_elem(&file_info_map, fikp);
    if (!fivp)
        return 0;

    fivp->fv_hint = inode->i_write_hint;
    if(iocb->ki_flags & IOCB_DIRECT)
        __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_DIRECT_WRITE], 1);
    else
        __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_BUFFER_WRITE], 1);
    return 0;
}

SEC("fentry/ext4_file_read_iter")
int BPF_PROG(my_ext4_file_read_iter,
    struct kiocb *iocb, struct iov_iter *to)
{
    struct file *file = iocb->ki_filp;
    struct inode *inode = file->f_inode;
    dev_t dev_cur = inode->i_sb->s_dev;
    struct file_info_key *fikp = NULL;
    struct file_info_val *fivp = NULL;
    u64 ino_id = inode->i_ino;
    if (dev_target && dev_target != dev_cur)
        return 0;

    fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp)
        return 0;
    fivp = bpf_map_lookup_elem(&file_info_map, fikp);
    if (!fivp)
        return 0;

    if (iocb->ki_flags & IOCB_DIRECT)
        __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_DIRECT_READ], 1);
    else
        __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_BUFFER_READ], 1);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
