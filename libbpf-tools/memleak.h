/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define MAX_HASH_ENTRY_NUM 1024*1024

#define INIT_UPROBE(name, pid, path, sym) \
{\
	off_t addr = get_elf_func_offset(path,sym);\
	if (addr < 0) {\
		fprintf(stderr, "cannot get offset of %s (libc: %s)\n", sym, path);\
		goto cleanup;\
	}\
	skel->links.uprobe_##name = bpf_program__attach_uprobe(skel->progs.uprobe_##name, \
							false, pid, path, addr);\
	err = libbpf_get_error(skel->links.uprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
}

#define INIT_URETPROBE(name, pid, path, sym) \
{\
	off_t addr = get_elf_func_offset(path,sym);\
	if (addr < 0) {\
		fprintf(stderr, "cannot get offset of %s (libc: %s)\n", sym, path);\
		goto cleanup;\
	}\
	skel->links.uretprobe_##name = bpf_program__attach_uprobe(skel->progs.uretprobe_##name, \
							true, pid, path, addr);\
	err = libbpf_get_error(skel->links.uretprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uretprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
}

#define INIT_UPROBE_URETPROBE(name, pid, path, sym) \
{\
	off_t addr = get_elf_func_offset(path,sym);\
	if (addr < 0) {\
		fprintf(stderr, "cannot get offset of %s (libc: %s)\n", sym, path);\
		goto cleanup;\
	}\
	skel->links.uprobe_##name = bpf_program__attach_uprobe(skel->progs.uprobe_##name, \
							false, pid, path, addr);\
	err = libbpf_get_error(skel->links.uprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
	skel->links.uretprobe_##name = bpf_program__attach_uprobe(skel->progs.uretprobe_##name, \
							true, pid, path, addr);\
	err = libbpf_get_error(skel->links.uretprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uretprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
}

struct alloc_info_t {
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
};

struct combined_alloc_info_t {
	__u64 total_size;
	__u64 number_of_allocs;
};

#endif /* __MEMLEAK_H */
