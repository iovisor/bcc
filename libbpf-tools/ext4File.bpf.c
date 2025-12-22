// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2025 Samsung Electronics Co., Ltd.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ext4File.h"

volatile __u64 device_num = 0;
volatile __u64 blocks_per_group = 0;
volatile __u64 system_up = 0;

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
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000000);
	__type(key, struct file_bg_key);
	__type(value, u64);
} file_bg_map SEC(".maps");

static __always_inline void *
bpf_map_lookup_and_delete(void *map, const void *key)
{
	void *val;

	val = bpf_map_lookup_elem(map, key);
	if (val){
		bpf_map_delete_elem(map, key);
	}
	
	return 0;
}

SEC("fexit/ext4_add_entry")
int BPF_PROG(my_ext4_add_nondir, handle_t* handle,
    struct dentry* dentry, struct inode* inode)
{
    struct inode* pa_inode = dentry->d_parent->d_inode;
    //bpf_probe_read_kernel(&inode, sizeof(inode), inodep);
    dev_t dev = pa_inode->i_sb->s_dev;
    u64 ino_id = inode->i_ino;
    struct file_info_key fik = {};
    struct file_info_val fiv = {}, *fivp;

    //bpf_printk("device_num:%d dev:%d\n", device_num, dev);
    if (device_num && device_num != dev)
        return 0;

    fik.fk_ino = ino_id;
    fik.fk_pa_ino = pa_inode->i_ino;
    bpf_probe_read_kernel(&fik.fk_name,
        sizeof(fik.fk_name), dentry->d_name.name);

    fiv.fv_access_cnt = 1;
    fiv.fv_ts[TS_TYPE_CREATE] =
        system_up + bpf_ktime_get_ns() / 1000000000ULL;

    if (bpf_map_update_elem(&file_info_map, &fik, &fiv, BPF_ANY))
        bpf_printk("failed to update file_info_map\n");
    if (bpf_map_update_elem(&ino_name_map, &ino_id, &fik, BPF_ANY))
        bpf_printk("failed to update ino_name_map\n");
    return 0;
}

SEC("fentry/ext4_file_write_iter")
int BPF_PROG(my_ext4_file_write_iter, 
    struct kiocb *iocb, struct iov_iter *from)
{
    struct file* file = iocb->ki_filp;
    struct inode* inode = file->f_inode;
    dev_t dev = inode->i_sb->s_dev;
    u64 cur_time = bpf_ktime_get_ns() / 1000000000ULL;
    struct file_info_key* fikp = NULL;
    struct file_info_val* fivp = NULL;
    u64 ino_id = inode->i_ino;
    long long offset = iocb-> ki_pos;
    if (device_num && device_num != dev)
        return 0;

    fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp) {
        bpf_printk("fail to find fikp: %d", ino_id);
        return 0;
    }

    fivp = bpf_map_lookup_elem(&file_info_map, fikp);
    if (!fivp) {
        bpf_printk("failed to lookup file_info_map\n");
        return 0;
    }

    fivp->fv_size = inode->i_size;
    fivp->fv_hint = inode->i_write_hint;
    fivp->fv_ts[TS_TYPE_MODIFY] = cur_time + system_up;
    __sync_fetch_and_add(&fivp->fv_access_cnt, 1);
    if(offset < fivp->fv_size) {
        __sync_fetch_and_add(&fivp->fv_update_cnt, 1);
    } else {
        if(iocb->ki_flags & IOCB_DIRECT)
            __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_DIRECT_WRITE], 1);
        else
            __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_BUFFER_WRITE], 1);
    }
    fivp->fv_ts[TS_TYPE_ACCESS] = cur_time + system_up;

    return 0;
}

SEC("fentry/ext4_file_read_iter")
int BPF_PROG(my_ext4_file_read_iter,
    struct kiocb *iocb, struct iov_iter *to)
{
    //bpf_printk("ext4_file_read_iter\n");
    struct file* file = iocb->ki_filp;
    struct inode* inode = file->f_inode;
    dev_t dev = inode->i_sb->s_dev;
    u64 cur_time = bpf_ktime_get_ns() / 1000000000ULL;
    struct file_info_key* fikp = NULL;
    struct file_info_val* fivp = NULL;
    u64 ino_id = inode->i_ino;
    //bpf_printk("device_num:%d dev:%d\n", device_num, dev);
    if (device_num && device_num != dev)
        return 0;

    fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp) {
        bpf_printk("fail to find fikp: %d", ino_id);
        return 0;
    }

    fivp = bpf_map_lookup_elem(&file_info_map, fikp);
    if (!fivp) {
        bpf_printk("failed to lookup file_info_map\n");
        return 0;
    }

    fivp->fv_size = inode->i_size;
    __sync_fetch_and_add(&fivp->fv_access_cnt, 1);
    if (iocb->ki_flags & IOCB_DIRECT)
        __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_DIRECT_READ], 1);
    else
        __sync_fetch_and_add(&fivp->fv_rw_cnt[RW_TYPE_BUFFER_READ], 1);
    fivp->fv_ts[TS_TYPE_ACCESS] = cur_time + system_up;

    return 0;
}

SEC("fentry/ext4_rmdir")
int BPF_PROG(my_ext4_rmdir,
    struct inode* dir, struct dentry* dentry) 
{
    struct inode* inode = dentry->d_inode;
    struct file_info_key* fikp = NULL;
    struct file_info_val* fivp = NULL;
    u64 cur_time = bpf_ktime_get_ns() / 1000000000ULL;
    u64 ino_id = inode->i_ino;

    fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp) {
        bpf_printk("fail to find fikp: %d", ino_id);
        return 0;
    }

    fivp = bpf_map_lookup_elem(&file_info_map, fikp);
    if (!fivp) {
        bpf_printk("fail to find fivp: %d", fivp);
        return 0;
    }
    fivp->fv_ts[TS_TYPE_ACCESS] = cur_time + system_up;
    fivp->fv_ts[TS_TYPE_DELETE] = cur_time + system_up;
    bpf_map_lookup_and_delete(&ino_name_map, &ino_id);
    return 0;
}

SEC("tp_btf/ext4_unlink_enter")
int BPF_PROG(my_ext4_unlink, 
    struct inode * pa_inode, struct dentry *dentry)
{
    struct inode* inode = dentry->d_inode;
    struct file_info_key* fikp = NULL;
    struct file_info_val* fivp = NULL;
    u64 cur_time = bpf_ktime_get_ns() / 1000000000ULL;
    u64 ino_id = inode->i_ino;
    
    fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp) {
        bpf_printk("fail to find fikp: %d", ino_id);
        return 0;
    }
    
    fivp = bpf_map_lookup_elem(&file_info_map, fikp);
    if (!fivp) {
        bpf_printk("fail to find fivp: %d", fivp);
        return 0;
    }
        
    fivp->fv_ts[TS_TYPE_ACCESS] = cur_time + system_up;
    fivp->fv_ts[TS_TYPE_DELETE] = cur_time + system_up;
	bpf_map_lookup_and_delete(&ino_name_map, &ino_id);
    return 0;
}

static void insert_file_bg_map(u64 bg_id, struct file_bg_key* fbgkp)
{
    u64 bit_pos = bg_id % GROUP;
    fbgkp->bgk_index = bg_id / GROUP;
    u64 n = flag(bit_pos);
    u64* t = bpf_map_lookup_elem(&file_bg_map, fbgkp);
    if (t)
        *t = *t | n;
    else {
        if(bpf_map_update_elem(&file_bg_map, fbgkp, &n, BPF_ANY))
            bpf_printk("failed to update file_bg_map\n");
    }      
}

SEC("tp_btf/ext4_ext_map_blocks_exit")
int BPF_PROG(my_ext4_ext_map_blocks_exit, struct inode *inode, unsigned int a,
			struct ext4_map_blocks *map, int flags) {	
    dev_t dev = inode->i_sb->s_dev;
    u32 ino_id = inode->i_ino;
    u64 phy_blk_beg = map->m_pblk;
    u64 phy_blk_end = map->m_pblk + map->m_len;
    u64 bg_id_beg = phy_blk_beg / blocks_per_group;
    u64 bg_id_end = phy_blk_end / blocks_per_group;
    struct file_bg_key fbgk = {};
    if (device_num && device_num != dev)
        return 0;
    struct file_info_key* fikp = bpf_map_lookup_elem(&ino_name_map, &ino_id);
    if (!fikp) {
        bpf_printk("failed to lookup ino_name_map: %d\n", ino_id);
        return 0;
    }
    fbgk.bgk_fik.fk_ino = fikp->fk_ino;
    fbgk.bgk_fik.fk_pa_ino = fikp->fk_pa_ino;
    bpf_probe_read_kernel(&fbgk.bgk_fik.fk_name,
        sizeof(fbgk.bgk_fik.fk_name), fikp->fk_name);
    insert_file_bg_map(bg_id_beg, &fbgk);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

