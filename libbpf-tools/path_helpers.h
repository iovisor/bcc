// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Rong Tao */
#ifndef __PATH_HELPERS_H
#define __PATH_HELPERS_H 1

#define NAME_MAX	255
#define MAX_PATH_DEPTH	32

struct full_path {
	/**
	 * Example: "/a/b/c/d"
	 * pathes[]: "|d\0     |c\0     |b\0     |a\0     |       |..."
	 *            |NAME_MAX|
	 */
	char pathes[NAME_MAX * MAX_PATH_DEPTH];
	unsigned int depth;
	int failed;
};

int print_full_path(struct full_path *path);
#endif
