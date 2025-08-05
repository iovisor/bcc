// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Rong Tao */
#pragma once
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>

#define CGROUP_DEFAULT_MNTPOINT	"/sys/fs/cgroup/"

/**
 * Get cgroup mountpoints.
 *
 * @roots need to be free with cgroup_free_roots(), access with roots[idx].
 *
 * On success, the number of root path returned, need pass to cgroup_free_roots()
 * nentries parameter. On error, -errno returned.
 */
int cgroup_get_roots(char ***roots);

/**
 * Used to release roots allocated by cgroup_get_roots().
 *
 * On success, zero returned. On error, -errno returned.
 */
int cgroup_free_roots(char **roots, int nentries);

/**
 * Get cgroup id from cgroup path.
 *
 * On success, the cgroupid returned. On error, -errno returned.
 */
long cgroup_cgroupid_of_path(const char *cgroup_path);
long cgroup_cgroupid_of_mnt_path(const char *mntpoint, const char *cgroup_path);

/**
 * Get cgroup path from cgroupid.
 *
 * On success, zero returned. On error, -errno returned.
 */
int cgroup_cgroup_path(long cgroupid, char *buf, size_t buf_len);

/**
 * This structure is used to describe a line of info in /proc/<pid>/cgroup.
 * For example, the following two entries show cgroupv1 and cgroupv2
 * respectively.
 *
 *   1:name=systemd:/user.slice/user-1000.slice/session-1.scope
 *   0::/user.slice/user-1000.slice/session-1.scope
 */
struct cgroup_proc_entry {
	/**
	 * 1: cgroup v1
	 * 2: cgroup v2
	 */
	int cgroup_type;
	/**
	 * The following variable stores a line of information from a
	 * /proc/<pid>/cgroup file.
	 */
	int hierarchy_id;
	char subsystem_list[256];
	char cgroup_path[PATH_MAX];
};

typedef void (*cgroup_proc_entry_fn)(const struct cgroup_proc_entry *cgrp, void *arg);

/**
 * This function traverses all cgroup information of a process, and each cgroup
 * entry will call the callback function.
 *
 * On success, the number of entry returned. On error, -errno returned.
 */
int cgroup_proc_for_each_cgroup_entry(pid_t pid, cgroup_proc_entry_fn callback,
				      void *arg);
