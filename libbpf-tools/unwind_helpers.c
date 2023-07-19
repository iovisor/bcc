/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Eunseon Lee
 *
 * 04-Feb-2023   Eunseon Lee   Created this.
 *
 * Post mortem Dwarf CFI based unwinding on top of regs and stack dumps.
 *
 * Lots of this code have been borrowed or heavily inspired from parts of
 * the libunwind and perf codes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <libunwind-ptrace.h>
#include <errno.h>
#include <dirent.h>
#include "unwind_helpers.h"

/* for internal logs */
#define p_debug(fmt, ...) __p(DEBUG, "Debug", fmt, ##__VA_ARGS__)
#define p_info(fmt, ...) __p(INFO, "Info", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...) __p(WARN, "Warn", fmt, ##__VA_ARGS__)
#define p_err(fmt, ...) __p(ERROR, "Error", fmt, ##__VA_ARGS__)

enum log_level {
	DEBUG,
	INFO,
	WARN,
	ERROR,
};

static struct sample_data *g_sample;
static size_t sample_ustack_size;
struct bpf_object *bpf_obj;

/*
 * default log level can be changed as needed.
 */
static enum log_level log_level = WARN;

void __p(enum log_level level, char *level_str, char *fmt, ...)
{
        va_list ap;

        if (level < log_level)
                return;
        va_start(ap, fmt);
        fprintf(stderr, "%s: ", level_str);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fflush(stderr);
}

/*
 * libunwind address space for post unwinding
 */
static int ptrace_access_mem (unw_word_t addr, unw_word_t *val, int write, pid_t pid)
{
	int i, end;
	unw_word_t tmp_val;

	/*
	 * Some 32-bit archs have to define a 64-bit unw_word_t.
	 * Callers of this function therefore expect a 64-bit
	 * return value, but ptrace only returns a 32-bit value
	 * in such cases.
	 */
	if (sizeof(long) == 4 && sizeof(unw_word_t) == 8)
		end = 2;
	else
		end = 1;

	for (i = 0; i < end; i++)
	{
		unw_word_t tmp_addr = i == 0 ? addr : addr + 4;

		errno = 0;
		if (write) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			tmp_val = i == 0 ? *val : *val >> 32;
#else
			tmp_val = i == 0 && end == 2 ? *val >> 32 : *val;
#endif

			p_debug("mem[%lx] <- %lx\n", (long) tmp_addr, (long) tmp_val);
			ptrace (PTRACE_POKEDATA, pid, tmp_addr, tmp_val);
			if (errno) {
				return -UNW_EINVAL;
			}
		}
		else {
			tmp_val = (unsigned long) ptrace (PTRACE_PEEKDATA, pid, tmp_addr, 0);
			if (i == 0)
				*val = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
			*val |= tmp_val << (i * 32);
#else
			*val |= i == 0 && end == 2 ? tmp_val << 32 : tmp_val;
#endif

			if (errno) {
				return -UNW_EINVAL;
			}
			p_debug("mem[%lx] -> %lx\n", (long) tmp_addr, (long) tmp_val);
		}
	}
	return 0;
}

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)
static inline void* uc_addr (unsigned long uc[], int reg)
{
	return &uc[reg];
}
#else
#error This Architecture is not supported yet. Please open an issue
#endif

static int access_reg(unw_addr_space_t as,
		      unw_regnum_t regnum, unw_word_t *val,
		      int __write, void *arg) //check. arg = u?
{
	unw_word_t *addr;
	struct sample_data *sample = g_sample;

	/* Don't support write, I suspect we don't need it. */
	if (__write) {
		p_err("unwind: access_reg w %d\n", regnum);
		return -EINVAL;
	}

	if (!(addr = uc_addr ((unsigned long*)&sample->user_regs, regnum))) {
		p_err("unwind: can't read reg %d\n", regnum);
		return -EINVAL;
	}

	*val = *(unw_word_t *) addr;
	p_debug("unwind: reg %d, val %lx\n", regnum, (unsigned long)*val);
	return 0;
}

static int access_mem(unw_addr_space_t as,
		      unw_word_t addr, unw_word_t *valp,
		      int __write, void *arg)
{
	struct sample_data *sample = g_sample;
	struct stack_dump *stack = &sample->user_stack;
	unw_word_t *start;
	unw_word_t end;
	int offset;
	int ret;
	//UPT_info *context = arg;
	pid_t pid = *(pid_t*)arg;

	/* Don't support write, probably not needed. */
	if (__write || !stack) {
		*valp = 0;
		p_err("unwind: invalid args\n");
		return -EINVAL;
	}

	if (!(start = uc_addr ((unsigned long*)&sample->user_regs, UNW_REG_SP))) {
		p_err("unwind: can't read reg SP\n");
		return -EINVAL;
	}

	end = *(unw_word_t *)start + (unw_word_t)(stack->size);

	/* Check overflow. */
	if (addr + sizeof(unw_word_t) < addr) {
		p_err("unwind: overflow, addr + sizeof(unw_word_t): %lx\n", addr + sizeof(unw_word_t));
		return -EINVAL;
	}

	if (addr < *start || addr + sizeof(unw_word_t) >= end) {
		//ret = ptrace_access_mem(addr, valp, __write, sample->pid);
		ret = ptrace_access_mem(addr, valp, __write, pid);
		if (ret) {
			p_warn("unwind: access_mem %p not inside range"
						 " 0x%" PRIx64 "-0x%" PRIx64 "\n",
						 (void *) (uintptr_t) addr, start, end);
			fprintf(stderr, "WARNING: The stack trace cannot be fully displayed."
				" Consider increasing sample stack size.\n");

			*valp = 0;
			return ret;
		}
		return 0;
	}

	offset = addr - *(unw_word_t *)start;
	*valp = *(unw_word_t *)&stack->data[offset];
	p_debug("unwind: start: %lx, end: %lx, addr: %p, offset: %lx\n",
		(unsigned long)*start, (unsigned long)end, (void*)(uintptr_t)addr, offset);
	p_debug("unwind: access_mem addr %p val %lx, offset %d\n",
	        (void *) (uintptr_t) addr, (unsigned long)*valp, offset);
	return 0;
}

static unw_accessors_t accessors = {
	.find_proc_info = _UPT_find_proc_info,
	.put_unwind_info = _UPT_put_unwind_info,
	.get_dyn_info_list_addr = _UPT_get_dyn_info_list_addr,
	.access_mem = access_mem,
	.access_reg = access_reg,
	.access_fpreg = _UPT_access_fpreg,
	.resume = _UPT_resume,
	.get_proc_name = _UPT_get_proc_name,
};

static int get_entries(struct sample_data *sample, pid_t pid,
		unsigned long *ip, int nr_ip)
{
	unw_cursor_t cursor;
	g_sample = sample;
	void *context = NULL;
	int err = 0;
	int i = 0;
	unw_addr_space_t as = unw_create_addr_space(&accessors, 0);

	if (!sample || !ip)
		return -EINVAL;

	if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
		p_err("ERROR: cannot attach to %d\n", pid);
		return -1;
	}

	context = _UPT_create(pid);
	if (!context) {
		err = -1;
		goto cleanup;
	}

	if (unw_init_remote(&cursor, as, context) != 0) {
		p_err("ERROR: cannot initialize cursor for remote unwinding\n");
		return -1;
	}

	do {
		unw_word_t pc;
		if (unw_get_reg(&cursor, UNW_REG_IP, &pc)) {
			p_err("ERROR: cannot read program counter\n");
			return -1;
		}

		ip[i++] = pc;
	} while (unw_step(&cursor) > 0 && i < nr_ip);

cleanup:
	if (context)
		_UPT_destroy(context);

	(void) ptrace(PTRACE_DETACH, pid, 0, 0);

	return err;
}

static inline unw_word_t stack_pointer(unsigned long uc[])
{
	return *(unw_word_t*)uc_addr(uc, UNW_REG_SP);
}

static void dump_stack(char* stack, size_t len)
{
	p_debug("stack data: \n");
	for (int i = 0; i < len; i++)
		p_debug("[%d]: %x ", i, stack[i*sizeof(long)]);
	p_debug("\n");
}

static void dump_regs(regs_dump_t *user_regs)
{
	p_debug("regs: \n");
	for (int i = 0; i <= UNW_REG_LAST; i++)
		p_debug("regs[%d]: 0x%llx\n", i, user_regs[i]);
}

static void dump_sample(int stack_id, struct sample_data *sample)
{
	p_debug("post unwind for stack %d\n", stack_id);
	dump_regs(&sample->user_regs);
	dump_stack(sample->user_stack.data, 20);
}

int unw_map_lookup_and_unwind_elem(const int ustack_id, pid_t pid,
				   unsigned long *ip, size_t nr_ip)
{
	int samples_map, ustacks_map;
	struct sample_data *sample = NULL;
	char *sample_ustack = NULL;
	int err;

	sample = (struct sample_data*)malloc(sizeof(struct sample_data));
	if (!sample)
		return -ENOMEM;

	sample_ustack = (char*)malloc(sample_ustack_size);
	if (!sample_ustack) {
		err = -ENOMEM;
		goto cleanup;
	}

	samples_map = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, SAMPLES_MAP_STR));
	if (samples_map < 0) {
		err = samples_map;
		goto cleanup;
	}
	ustacks_map = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, USTACKS_MAP_STR));
	if (ustacks_map < 0) {
		err = ustacks_map;
		goto cleanup;
	}

	err = bpf_map_lookup_elem(samples_map, &ustack_id, sample);
	if (err < 0) {
		fprintf(stderr, "failed to lookup samples for stack %d: %d\n", ustack_id, err);
		goto cleanup;
	}

	err = bpf_map_lookup_elem(ustacks_map, &ustack_id, sample_ustack);
	if (err < 0) {
		fprintf(stderr, "failed to lookup ustacks for stack %d: %d\n", ustack_id, err);
		goto cleanup;
	}
	sample->user_stack.data = sample_ustack;

	dump_sample(ustack_id, sample);

	err = get_entries(sample, pid, ip, nr_ip);
	if (err)
		p_err("get_entries failded: %d\n", err);

cleanup:
	if (sample->user_stack.data)
		free(sample->user_stack.data);
	if (sample)
		free(sample);

	return err;
}

int unw_map__set(struct bpf_object *obj, size_t ustack_size, size_t max_entries)
{
	struct bpf_map *samples_map = bpf_object__find_map_by_name(obj, SAMPLES_MAP_STR);
	struct bpf_map *ustacks_map = bpf_object__find_map_by_name(obj, USTACKS_MAP_STR);

	if (samples_map < 0 || ustacks_map < 0)
		return -EINVAL;

	bpf_map__set_max_entries(samples_map, max_entries);
	bpf_map__set_value_size(ustacks_map, ustack_size);
	bpf_map__set_max_entries(ustacks_map, max_entries);

	sample_ustack_size = ustack_size;
	bpf_obj = obj;

	return 0;
}
