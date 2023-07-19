/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __UNWIND_HELPERS_H
#define __UNWIND_HELPERS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <libunwind-ptrace.h>
#include "unwind_types.h"

#define UNW_SET_ENV(obj, user_stack_size, max_entries) 		\
({								\
	obj->rodata->sample_user_stack = true; 			\
	obj->rodata->sample_ustack_size = user_stack_size; 	\
	obj->rodata->sample_max_entries = max_entries; 		\
	unw_map__set(obj->obj, user_stack_size, max_entries); 	\
})

int unw_map__set(struct bpf_object *obj, size_t sample_ustack_size, size_t max_entries);

/*
 * unw_map_lookup_and_unwind_elem
 *
 * allows to lookup BPF map value corresponding to provided key.
 *
 * @brief **bpf_map__lookup_elem()** allows to lookup BPF map value
 * corresponding to provided key.
 * @key: user stack id to lookup and unwind
 * @pid: process id of @key
 * @user_stack_size: max size to store each user stack
 * @obj: bpf_object
 * @value: pointer to memory in which unwounded value will be stored
 * @value_sz: size in byte of value data memory
 * @len: size of @value
 *
 * This function returns id of dumped user stack and registers for current context
 * 	Perform a lookup in *map* for an entry associated to *key*.
 */
int unw_map_lookup_and_unwind_elem(const int ustack_id, pid_t pid,
				   unsigned long *value, size_t value_sz);


#endif /* __UNWIND_HELPERS_H */
