// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static bool batch_map_ops = true; /* hope for the best */

static int
dump_hash_iter(int map_fd, void *keys, __u32 key_size,
	       void *values, __u32 value_size, __u32 *count,
	       void *invalid_key)
{
	__u8 key[key_size], next_key[key_size];
	__u32 n = 0;
	int i, err;

	/* First get keys */
	__builtin_memcpy(key, invalid_key, key_size);
	while (n < *count) {
		err = bpf_map_get_next_key(map_fd, key, next_key);
		if (err && errno != ENOENT) {
			return -1;
		} else if (err) {
			break;
		}
		__builtin_memcpy(key, next_key, key_size);
		__builtin_memcpy(keys + key_size * n, next_key, key_size);
		n++;
	}

	/* Now read values */
	for (i = 0; i < n; i++) {
		err = bpf_map_lookup_elem(map_fd, keys + key_size * i,
					  values + value_size * i);
		if (err)
			return -1;
	}

	*count = n;
	return 0;
}

static int
dump_hash_batch(int map_fd, void *keys, __u32 key_size,
		void *values, __u32 value_size, __u32 *count)
{
	void *in = NULL, *out;
	__u32 n, n_read = 0;
	int err = 0;

	while (n_read < *count && !err) {
		n = *count - n_read;
		err = bpf_map_lookup_batch(map_fd, &in, &out,
					   keys + n_read * key_size,
					   values + n_read * value_size,
					   &n, NULL);
		if (err && errno != ENOENT) {
			return -1;
		}
		n_read += n;
		in = out;
	}

	*count = n_read;
	return 0;
}

int dump_hash(int map_fd,
	      void *keys, __u32 key_size,
	      void *values, __u32 value_size,
	      __u32 *count, void *invalid_key)
{
	int err;

	if (!keys || !values || !count || !key_size || !value_size) {
		errno = EINVAL;
		return -1;
	}

	if (batch_map_ops) {
		err = dump_hash_batch(map_fd, keys, key_size,
				      values, value_size, count);
		if (err && errno == EINVAL) {
			/* assume that batch operations are not
			 * supported and try non-batch mode */
			batch_map_ops = false;
		} else {
			return err;
		}
	}

	if (!invalid_key) {
		errno = EINVAL;
		return -1;
	}

	return dump_hash_iter(map_fd, keys, key_size,
			      values, value_size, count, invalid_key);
}
