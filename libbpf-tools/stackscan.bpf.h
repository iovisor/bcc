/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __STACKSCAN_BPF_H
#define __STACKSCAN_BPF_H

/*
 * Stack scan based similar backtrace on top of regs and stack dumps.
 *
 * Iterate through the stacks, starting with the current stack pointer and
 * collect any text addresses we find.
 * This also serves as a failsafe option in case the unwinder goes off in the weeds.
 *
 * The idea has been borrowed or heavily inspired from parts of the linux codes.
 * (arch/x86/kernel/dumpstack.c)
 */

/*
 * This macro can be defined to change the default before including this helper.
 * This value is used to set the resource size for stack scan.$
 *
 * #define STACK_SIZE		128  Stack storage size to store per user stack
 * #define MAX_RANGE_NR		15   Maximum number of text ranges to save
 * #define MAX_ADDR_NR		32   Maximum number of addresses to store per user stack
 */
#if !defined(STACK_SIZE)
#define STACK_SIZE		128
#endif

#if !defined(MAX_RANGE_NR)
#define MAX_RANGE_NR		16
#endif

#if !defined(MAX_ADDR_NR)
#define MAX_ADDR_NR		32
#endif

#define min(a, b)	(a < b ? a : b)

#ifdef DEBUG
#ifdef bpf_dbg_printk
#error bpf_dbg_printk cannot be redefinded.
#endif

#define bpf_dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_dbg_printk(fmt, ...) ;
#endif

/*
 * Limit maximum number of iterations with bpf resource limit.
 */
/* The maximum number of iterations of the scan that
 * does not exceed the insn limit of the bpf program.
 */
#define MAX_SCAN_NR		10
/* The maximum number of iterations of the read VMA that
 * does not exceed the insn limit of the bpf program.
 */
#define MAX_VMA_NR		10

/*
 * vma
 */
#define VM_EXEC         0x00000004  /* include/linux/mm.h */

/*
 * bpf maps for stack scanning
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__type(value, __u64[MAX_ADDR_NR]);
	__uint(max_entries, MAX_ENTRIES);
} scan_map SEC(".maps");

/* Temporary buffer to compensate for stack limit */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, STACK_SIZE);
} stack_storage_map SEC(".maps");

/* Temporary buffer to compensate for stack limit */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, __u64[MAX_ADDR_NR]);
} addrs_storage_map SEC(".maps");

static __always_inline
bool is_code_addr(u64 addr, const unsigned long ranges[][2], int nr_range)
{
	int i;

	for (i = 0; ranges[i][0] && i < nr_range; i++) {
		if (ranges[i][0] <= addr && addr <= ranges[i][1])
			return true;
	}

	return false;
}

static void get_code_ranges(struct mm_struct *mm, unsigned long ranges[][2], int nr)
{
	int i = 0;
	int j;

	if (mm) {
		struct vm_area_struct *vma = BPF_CORE_READ(mm, mmap);

		/* CAUTION: exit condition of for loop should be countable.
		 * for example, exit condition like below is not allowed.
		 * for (; vma; vma = BPF_CORE_READ(vma, vm_next)) {
		 * for (j = 0; vma && j < MAX_VMA_NR && i < MAX_RANGE_NR; vma = BPF_CORE_READ(vma, vm_next), j++) {
		 */
		for (j = 0; vma && j < MAX_VMA_NR; vma = BPF_CORE_READ(vma, vm_next), j++) {
			if (!(BPF_CORE_READ(vma, vm_flags) & VM_EXEC))
				continue;

			/* CAUTION: number of range should be set to avoid overflow because it can't be checked as exit condition of for loop */
			ranges[i][0] = BPF_CORE_READ(vma, vm_start);
			ranges[i][1] = BPF_CORE_READ(vma, vm_end);
			bpf_dbg_printk("[text %d] 0x%lx ~ 0x%lx\n", j, ranges[i][0], ranges[i][1]);
			i++;
		}
	}
}

/*
 * get_scan_user_stackid - get stack id of similar-backtrace for @ctx
 * @ctx: context to get similar-backtrace
 * @stack_storage_size: maximun buffer size to save user stacks
 *
 * This function returns a stack id of text addresses
 * that looked up in user stacks in the context
 */
static int get_scan_user_stackid(struct pt_regs *ctx, const volatile unsigned long stack_storage_size)
{
	int ret;
	u64 sp, pc, lr;
	int i = 0, j;
	u32 stack_len;
	__u64* stack;
	__u64 addr;
	__u64* addrs;
	static __u32 id = -1;
	static const __u32 storage_id = 0;
	struct task_struct *task;
	struct mm_struct *mm;
	int nr_scan;
	unsigned long ranges[MAX_RANGE_NR][2] = {0,};

	task = bpf_get_current_task_btf();
	mm = BPF_CORE_READ(task, mm);
	ctx = (struct pt_regs*)bpf_task_pt_regs(task);
	if (!ctx)
		return -1;

	stack = bpf_map_lookup_elem(&stack_storage_map, &storage_id);
	if (!stack) {
		bpf_printk("stack storage is null\n");
		return -1;
	}
	addrs = bpf_map_lookup_elem(&addrs_storage_map, &storage_id);
	if (!addrs) {
		bpf_printk("addrs storage is null\n");
		return -1;
	}
	__builtin_memset(addrs, 0x0, sizeof(addrs) * MAX_ADDR_NR);

	__sync_fetch_and_add(&id, 1);
	if (id >= MAX_ENTRIES)
		return -1;

	/* Get user regs */
	pc = PT_REGS_IP_CORE(ctx);
	lr = PT_REGS_RET_CORE(ctx);
	sp = PT_REGS_SP_CORE(ctx);
	addrs[i++] = pc;
	addrs[i++] = lr;
	bpf_dbg_printk("pc: 0x%lx, sp: 0x%lx, lr: 0x%lx\n", pc, sp, lr);

	/* Get user stacks */
	if (!mm)
		goto store_addrs;

	/* stack length to read */
	stack_len = BPF_CORE_READ(mm, start_stack) - sp;
	stack_len = min(stack_len, stack_storage_size);
	bpf_dbg_printk("stack_len: %d\n", stack_len);

	ret = bpf_probe_read_user(stack, stack_len, (void*)sp);
	if (ret != 0) {
		bpf_printk("failed to read stack: %d\n", ret);
		goto store_addrs;
	}

	get_code_ranges(mm, ranges, MAX_RANGE_NR);

	nr_scan = min(stack_len/sizeof(addr), MAX_SCAN_NR);

	/* Scan stacks */
	for (j = 0; j < nr_scan && i < MAX_ADDR_NR; j++) {
		addr = stack[j];

		if (is_code_addr(addr, ranges, MAX_RANGE_NR))
			addrs[i++] = addr;
        }

store_addrs:
	/* Store addrs */
	ret = bpf_map_update_elem(&scan_map, &id, addrs, BPF_NOEXIST);
	if (ret != 0) {
		bpf_printk("failed to update scan_map: %d\n", ret);
		goto cleanup;
	}

	return id;

cleanup:
	return -1;
}
#endif /* __STACKSCAN_BPF_H */
