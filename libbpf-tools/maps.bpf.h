// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <bpf/bpf_helpers.h>
#include <asm-generic/errno.h>

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	/* bpf helper functions like bpf_map_update_elem() below normally return
	 * long, but using int instead of long to store the result is a workaround
	 * to avoid incorrectly evaluating err in cases where the following criteria
	 * is met:
	 *     the architecture is 64-bit
	 *     the helper function return type is long
	 *     the helper function returns the value of a call to a bpf_map_ops func
	 *     the bpf_map_ops function return type is int
	 *     the compiler inlines the helper function
	 *     the compiler does not sign extend the result of the bpf_map_ops func
	 *
	 * if this criteria is met, at best an error can only be checked as zero or
	 * non-zero. it will not be possible to check for a negative value or a
	 * specific error value. this is because the sign bit would have been stuck
	 * at the 32nd bit of a 64-bit long int.
	 */
	int err;

	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;

	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
		return 0;

	return bpf_map_lookup_elem(map, key);
}

#endif /* __MAPS_BPF_H */
