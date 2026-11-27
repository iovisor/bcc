// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2023 LG Electronics Inc.
#ifndef __UNWIND_HELPERS_H
#define __UNWIND_HELPERS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libunwind-ptrace.h>
#include "unwind_helpers_types.h"

/*
 * How to Use
 *
 * For the helloworld tool:
 *
 * For helloworld.bpf.c:
 * 1. Include unwind_helpers.bpf.h
 * 2. Use uw_get_stackid() to obtain the stack ID
 *
 * For helloworld.c:
 * 1. Include unwind_helpers.h
 * 2. Call UW_MAP_SET before invoking *_bpf__load to init resource sizes in unwind_helper
 * 3. Call uw_map_lookup_elem to retrieve ips for the stack ID.
 *
 * Additional Information
 * Register dumps and stack dumps are stored in internal maps in unwind_helpers.
 * The size of these maps can be configured using UW_MAP_SET().
 */

/*
 * UW_MAP_SET(obj, stack_size, uw_max_entries)
 *
 * @obj: bpf_object
 * @stack_size: max size to store each user stack
 * @uw_max_entries: max entries to store user stacks
 */
#define UW_MAP_SET(o, stack_size, uw_max_entries) 		\
({								\
	o->rodata->dwarf_unwind = true;				\
	o->rodata->targ_ustack_size = stack_size;		\
	o->rodata->targ_sample_max_entries = uw_max_entries;	\
	uw_map__set(o->obj, stack_size, uw_max_entries);	\
})
int uw_map__set(const struct bpf_object *obj, size_t stack_size, size_t max_entries);

/*
 * uw_map_lookup_elem
 *
 * allows to lookup BPF map value corresponding to stack_id.
 *
 * @brief **bpf_map__lookup_elem()** allows to lookup BPF map value
 * corresponding to provided key.
 * @stack_id: user stack id to lookup and unwind
 * @pid: process id of @stack_id
 * @ip: pointer to memory in which unwounded value will be stored
 * @count: number of value data memory
 *
 * This function returns id of dumped user stack and registers for current context
 * 	Perform a lookup in *map* for an entry associated to *stack_id*.
 */
int uw_map_lookup_elem(const int *stack_id, pid_t pid,
		       unsigned long *ip, size_t count);

#endif /* __UNWIND_HELPERS_H */
