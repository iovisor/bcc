// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Rong Tao */
#include <stdio.h>
#include "path_helpers.h"


int print_full_path(struct full_path *path)
{
	int n = 0, depth;

	for (depth = path->depth; depth >= 0; depth--) {
		char *fname = (char *)&path->pathes[NAME_MAX * depth];

		/**
		 * If it is a mount point, there will be a '/', because
		 * the '/' will be added below, so just skip this '/'.
		 */
		if (fname[0] == '/' && fname[1] == '\0')
			continue;

		/**
		 * 1. If the file/path name starts with '/', do not
		 *    print the '/' prefix.
		 * 2. If bpf_probe_read_kernel_str() fails, or the
		 *    directory depth reaches the upper limit
		 *    MAX_PATH_DEPTH, the top-level directory
		 *    is printed without the prefix '/'.
		 */
		n = printf("%s%s",
			"/\0" + (fname[0] == '/' ||
				 ((path->failed || path->depth == MAX_PATH_DEPTH - 1) &&
				  depth == path->depth)),
			fname);
	}
	return n;
}
