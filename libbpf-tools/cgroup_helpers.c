// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Rong Tao */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include "cgroup_helpers.h"


/**
 * Get cgroup mountpoints.
 *
 * @roots need to be free with cgroup_free_roots(), access with roots[idx].
 *
 * On success, the number of root path returned, need pass to cgroup_free_roots()
 * nentries parameter. On error, -errno returned.
 */
static int cgroup_get_roots(char ***roots)
{
	char line[2048], fsname[128], mntpoint[PATH_MAX], fstype[64], mntopt[256];
	int dump_frequency, fsck_order, n;
	FILE *fp;

	n = 0;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return -errno;

	*roots = NULL;

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%s %s %s %s %d %d\n", fsname, mntpoint,
			fstype, mntopt, &dump_frequency,
			&fsck_order) != 6)
			continue;

		/* Only need cgroup or cgroup2 */
		if (strcmp(fstype, "cgroup") && strcmp(fstype, "cgroup2"))
			continue;

		n++;
		*roots = (char **)realloc(*roots, n * sizeof(char *));
		(*roots)[n - 1] = strdup(mntpoint);
	}

	fclose(fp);

	return n;
}

/**
 * Used to release roots allocated by cgroup_get_roots().
 *
 * On success, zero returned. On error, -errno returned.
 */
static int cgroup_free_roots(char **roots, int nentries)
{
	int i;

	if (!roots)
		return -EINVAL;

	for (i = 0; i < nentries; i++)
		free(roots[i]);
	free(roots);

	return 0;
}

long cgroup_cgroupid_of_path(const char *cgroup_path)
{
	int err;
	struct stat st;
	/* The inode of the cgroup folder is the groupid */
	err = stat(cgroup_path, &st);
	return err ? -errno : st.st_ino;
}

typedef int (*match_fn)(const char *path, void *arg);

/**
 * Recursively traverse all directories under the known cgroup root for
 * matching.
 *
 * When @match returns true, the match succeeds and the function returns
 * without further searching.
 *
 * If the match is successful, 1 is returned. If the match fails, 0 is returned.
 * If an error occurs during the search process, -errno is returned.
 */
static int find_cgroup_from_root_recur(const char *root, match_fn match,
				       void *arg)
{
	int err = 0;
	DIR *dir;
	struct dirent *dirent;
	char *path;
	struct stat st;
	size_t path_len;

	assert(match && "match_fn is NULL");

	if (!root)
		return -EINVAL;

	err = lstat(root, &st);
	if (err)
		return -errno;
	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;

	path = malloc(PATH_MAX);
	if (!path)
		return -errno;

	snprintf(path, PATH_MAX - 1, "%s/", root);

	err = lstat(path, &st);
	if (err)
		return -errno;
	if (!S_ISDIR(st.st_mode)) {
		free(path);
		return -ENOENT;
	}

	dir = opendir(path);
	if (!dir) {
		err = -errno;
		goto done;
	}

	path_len = strlen(path);

	/**
	 * If the directory path doesn't end with a slash, append a slash,
	 * convenient for splicing subdirectories.
	 */
	if (path[path_len - 1] != '/') {
		path[path_len] = '/';
		path[++path_len] = '\0';
	}

	/**
	 * Traverse all folders under the root directory, skipping the current
	 * directory and the previous directory.
	 */
	while ((dirent = readdir(dir)) != NULL) {
		if (!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, ".."))
			continue;
		strncpy(path + path_len, dirent->d_name, PATH_MAX - path_len);
		err = lstat(path, &st);
		if (err)
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;
#ifdef DEBUG
		fprintf(stderr, "%s\n", path);
#endif
		if (match(path, arg)) {
			/* Found */
			err = 1;
			goto done;
		}

		/**
		 * Recursive search. Returning 1 means it was found, return
		 * -errno means an error occurred, and returning 0 means it
		 * was not found and should continue searching.
		 */
		err = find_cgroup_from_root_recur(path, match, arg);
		if (err)
			goto done;
	}

	/* Not found */
	err = 0;
done:
	closedir(dir);
	free(path);
	return err;
}

struct match_cgroupid_arg {
	long cgroupid;
	char path[PATH_MAX];
};

/**
 * As the @match parameter of the find_cgroup_from_root_recur() function,
 * the cgroup path is found by cgroupid.
 */
static int match_cgroupid(const char *path, void *arg)
{
	long cgroupid;
	struct match_cgroupid_arg *a = arg;

	cgroupid = cgroup_cgroupid_of_path(path);
#ifdef DEBUG
	fprintf(stderr, "%ld:%ld %s\n", cgroupid, a->cgroupid, path);
#endif
	if (cgroupid == a->cgroupid) {
		snprintf(a->path, PATH_MAX, path);
		return 1;
	}
	return 0;
}

int get_cgroupid_path(long cgroupid, char *buf, size_t buf_len)
{
	char **roots = 0;
	int nroots, i, err;
	struct match_cgroupid_arg arg = {};
	bool found = false;

	arg.cgroupid = cgroupid;

	nroots = cgroup_get_roots(&roots);

	for (i = 0; i < nroots; i++) {
#ifdef DEBUG
		fprintf(stderr, "root --- %s\n", roots[i]);
#endif
		err = find_cgroup_from_root_recur(roots[i], match_cgroupid, &arg);
		if (err == 1) {
			strncpy(buf, arg.path, buf_len);
			found = true;
			break;
		}
	}

	cgroup_free_roots(roots, nroots);

	return found ? 0 : -ENOENT;
}
