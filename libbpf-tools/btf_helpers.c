/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <zlib.h>

#include "trace_helpers.h"
#include "btf_helpers.h"

extern unsigned char _binary_min_core_btfs_tar_gz_start[] __attribute__((weak));
extern unsigned char _binary_min_core_btfs_tar_gz_end[] __attribute__((weak));

#define FIELD_LEN 65
#define ID_FMT "ID=%64s"
#define VERSION_FMT "VERSION_ID=\"%64s"

struct os_info {
	char id[FIELD_LEN];
	char version[FIELD_LEN];
	char arch[FIELD_LEN];
	char kernel_release[FIELD_LEN];
};

static struct os_info * get_os_info()
{
	struct os_info *info = NULL;
	struct utsname u;
	size_t len = 0;
	ssize_t read;
	char *line = NULL;
	FILE *f;

	if (uname(&u) == -1)
		return NULL;

	f = fopen("/etc/os-release", "r");
	if (!f)
		return NULL;

	info = calloc(1, sizeof(*info));
	if (!info)
		goto out;

	strncpy(info->kernel_release, u.release, FIELD_LEN);
	strncpy(info->arch, u.machine, FIELD_LEN);

	while ((read = getline(&line, &len, f)) != -1) {
		if (sscanf(line, ID_FMT, info->id) == 1)
			continue;

		if (sscanf(line, VERSION_FMT, info->version) == 1) {
			/* remove '"' suffix */
			info->version[strlen(info->version) - 1] = 0;
			continue;
		}
	}

out:
	free(line);
	fclose(f);

	return info;
}

#define INITIAL_BUF_SIZE (1024 * 1024 * 4) /* 4MB */

/* adapted from https://zlib.net/zlib_how.html */
static int
inflate_gz(unsigned char *src, int src_size, unsigned char **dst, int *dst_size)
{
	size_t size = INITIAL_BUF_SIZE;
	size_t next_size = size;
	z_stream strm;
	void *tmp;
	int ret;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;

	ret = inflateInit2(&strm, 16 + MAX_WBITS);
	if (ret != Z_OK)
		return -EINVAL;

	*dst = malloc(size);
	if (!*dst)
		return -ENOMEM;

	strm.next_in = src;
	strm.avail_in = src_size;

	/* run inflate() on input until it returns Z_STREAM_END */
	do {
		strm.next_out = *dst + strm.total_out;
		strm.avail_out = next_size;
		ret = inflate(&strm, Z_NO_FLUSH);
		if (ret != Z_OK && ret != Z_STREAM_END)
			goto out_err;
		/* we need more space */
		if (strm.avail_out == 0) {
			next_size = size;
			size *= 2;
			tmp = realloc(*dst, size);
			if (!tmp) {
				ret = -ENOMEM;
				goto out_err;
			}
			*dst = tmp;
		}
	} while (ret != Z_STREAM_END);

	*dst_size = strm.total_out;

	/* clean up and return */
	ret = inflateEnd(&strm);
	if (ret != Z_OK) {
		ret = -EINVAL;
		goto out_err;
	}
	return 0;

out_err:
	free(*dst);
	*dst = NULL;
	return ret;
}

/* tar header from https://github.com/tklauser/libtar/blob/v1.2.20/lib/libtar.h#L39-L60 */
struct tar_header {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
	char padding[12];
};

static char *tar_file_start(struct tar_header *tar, const char *name, int *length)
{
	while (tar->name[0]) {
		sscanf(tar->size, "%o", length);
		if (!strcmp(tar->name, name))
			return (char *)(tar + 1);
		tar += 1 + (*length + 511)/512;
	}
	return NULL;
}

int ensure_core_btf(struct bpf_object_open_opts *opts)
{
	char name_fmt[] = "./%s/%s/%s/%s.btf";
	char btf_path[] = "/tmp/bcc-libbpf-tools.btf.XXXXXX";
	struct os_info *info = NULL;
	unsigned char *dst_buf = NULL;
	char *file_start;
	int dst_size = 0;
	char name[100];
	FILE *dst = NULL;
	int ret;

	/* do nothing if the system provides BTF */
	if (vmlinux_btf_exists())
		return 0;

	/* compiled without min core btfs */
	if (!_binary_min_core_btfs_tar_gz_start)
		return -EOPNOTSUPP;

	info = get_os_info();
	if (!info)
		return -errno;

	ret = mkstemp(btf_path);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}

	dst = fdopen(ret, "wb");
	if (!dst) {
		ret = -errno;
		goto out;
	}

	ret = snprintf(name, sizeof(name), name_fmt, info->id, info->version,
		       info->arch, info->kernel_release);
	if (ret < 0 || ret == sizeof(name)) {
		ret = -EINVAL;
		goto out;
	}

	ret = inflate_gz(_binary_min_core_btfs_tar_gz_start,
			 _binary_min_core_btfs_tar_gz_end - _binary_min_core_btfs_tar_gz_start,
			 &dst_buf, &dst_size);
	if (ret < 0)
		goto out;

	ret = 0;
	file_start = tar_file_start((struct tar_header *)dst_buf, name, &dst_size);
	if (!file_start) {
		ret = -EINVAL;
		goto out;
	}

	if (fwrite(file_start, 1, dst_size, dst) != dst_size) {
		ret = -ferror(dst);
		goto out;
	}

	opts->btf_custom_path = strdup(btf_path);
	if (!opts->btf_custom_path)
		ret = -ENOMEM;

out:
	free(info);
	fclose(dst);
	free(dst_buf);

	return ret;
}

void cleanup_core_btf(struct bpf_object_open_opts *opts) {
	if (!opts)
		return;

	if (!opts->btf_custom_path)
		return;

	unlink(opts->btf_custom_path);
	free((void *)opts->btf_custom_path);
}
