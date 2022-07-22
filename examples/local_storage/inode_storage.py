#!/usr/bin/python3

from bcc import BPF

source = r"""
#include <linux/fs.h>

BPF_INODE_STORAGE(inode_storage_map, int);

LSM_PROBE(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	  struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	int *value;

	value = inode_storage_map.inode_storage_get(old_dentry->d_inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!value)
		return 0;

	bpf_trace_printk("%d", *value);
	return 0;
}
"""

b = BPF(text=source)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
