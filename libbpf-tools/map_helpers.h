/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Anton Protopopov */
#ifndef __MAP_HELPERS_H
#define __MAP_HELPERS_H

#include <bpf/bpf.h>

int dump_hash(int map_fd, void *keys, __u32 key_size,
	      void *values, __u32 value_size, __u32 *count, void *invalid_key);

#endif /* __MAP_HELPERS_H */
