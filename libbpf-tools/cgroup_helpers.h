// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Rong Tao */
#pragma once
#include <sys/types.h>


/**
 * Get cgroup id from cgroup path.
 *
 * On success, the cgroupid returned. On error, -errno returned.
 */
long cgroup_cgroupid_of_path(const char *cgroup_path);

/**
 * Get cgroup path from cgroupid.
 *
 * On success, zero returned. On error, -errno returned.
 */
int get_cgroupid_path(long cgroupid, char *buf, size_t buf_len);
