/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define DISK_NAME_LEN	32

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)	(((ma) << MINORBITS) | (mi))

struct ksyms {
	struct ksym *syms;
	int syms_sz;
	int syms_cap;
	char *strs;
	int strs_sz;
	int strs_cap;
};

static int ksyms__add_symbol(struct ksyms *ksyms, const char *name, unsigned long addr)
{
	size_t new_cap, name_len = strlen(name) + 1;
	struct ksym *ksym;
	void *tmp;

	if (ksyms->strs_sz + name_len > ksyms->strs_cap) {
		new_cap = ksyms->strs_cap * 4 / 3;
		if (new_cap < ksyms->strs_sz + name_len)
			new_cap = ksyms->strs_sz + name_len;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->strs, new_cap);
		if (!tmp)
			return -1;
		ksyms->strs = tmp;
		ksyms->strs_cap = new_cap;
	}
	if (ksyms->syms_sz + 1 > ksyms->syms_cap) {
		new_cap = ksyms->syms_cap * 4 / 3;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->syms, sizeof(*ksyms->syms) * new_cap);
		if (!tmp)
			return -1;
		ksyms->syms = tmp;
		ksyms->syms_cap = new_cap;
	}

	ksym = &ksyms->syms[ksyms->syms_sz];
	/* while constructing, re-use pointer as just a plain offset */
	ksym->name = (void *)(unsigned long)ksyms->strs_sz;
	ksym->addr = addr;

	memcpy(ksyms->strs + ksyms->strs_sz, name, name_len);
	ksyms->strs_sz += name_len;
	ksyms->syms_sz++;

	return 0;
}

static int ksym_cmp(const void *p1, const void *p2)
{
	const struct ksym *s1 = p1, *s2 = p2;

	if (s1->addr == s2->addr)
		return strcmp(s1->name, s2->name);
	return s1->addr < s2->addr ? -1 : 1;
}

struct ksyms *ksyms__load(void)
{
	char sym_type, sym_name[256];
	struct ksyms *ksyms;
	unsigned long sym_addr;
	int i, ret;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return NULL;

	ksyms = calloc(1, sizeof(*ksyms));
	if (!ksyms)
		goto err_out;

	while (true) {
		ret = fscanf(f, "%lx %c %s%*[^\n]\n",
			     &sym_addr, &sym_type, sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 3)
			goto err_out;
		if (ksyms__add_symbol(ksyms, sym_name, sym_addr))
			goto err_out;
	}

	/* now when strings are finalized, adjust pointers properly */
	for (i = 0; i < ksyms->syms_sz; i++)
		ksyms->syms[i].name += (unsigned long)ksyms->strs;

	qsort(ksyms->syms, ksyms->syms_sz, sizeof(*ksyms->syms), ksym_cmp);

	fclose(f);
	return ksyms;

err_out:
	ksyms__free(ksyms);
	fclose(f);
	return NULL;
}

void ksyms__free(struct ksyms *ksyms)
{
	if (!ksyms)
		return;

	free(ksyms->syms);
	free(ksyms->strs);
	free(ksyms);
}

const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr)
{
	int start = 0, end = ksyms->syms_sz - 1, mid;
	unsigned long sym_addr;

	/* find largest sym_addr <= addr using binary search */
	while (start < end) {
		mid = start + (end - start + 1) / 2;
		sym_addr = ksyms->syms[mid].addr;

		if (sym_addr <= addr)
			start = mid;
		else
			end = mid - 1;
	}

	if (start == end && ksyms->syms[start].addr <= addr)
		return &ksyms->syms[start];
	return NULL;
}

const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name)
{
	int i;

	for (i = 0; i < ksyms->syms_sz; i++) {
		if (strcmp(ksyms->syms[i].name, name) == 0)
			return &ksyms->syms[i];
	}

	return NULL;
}

struct load_range {
	uint64_t start;
	uint64_t end;
	uint64_t file_off;
};

enum elf_type {
	EXEC,
	DYN,
	PERF_MAP,
	VDSO,
	UNKNOWN,
};

/* How the ELF backing a mapping was located; used for diagnostics only. */
enum dso_open_method {
	DSO_OPEN_FAILED = 0,
	DSO_OPEN_MAP_FILES,	/* /proc/<tgid>/map_files/<start>-<end> */
	DSO_OPEN_PROC_ROOT,	/* /proc/<tgid>/root/<path> */
	DSO_OPEN_RAW_PATH,	/* <path>, as seen from our own mount ns */
};

struct dso {
	char *name;
	struct load_range *ranges;
	int range_sz;
	/* Dyn's first text section virtual addr at execution */
	uint64_t sh_addr;
	/* Dyn's first text section file offset */
	uint64_t sh_offset;
	enum elf_type type;

	/* Backing ELF fd, kept open until the symbol table has been read. */
	int fd;
	enum dso_open_method open_method;
	/* locator, to re-open the backing ELF if fd was given up */
	pid_t tgid;
	uint64_t loc_start;
	uint64_t loc_end;
	/* file identity from maps, used to merge the VMAs of one ELF */
	uint64_t dev;
	uint64_t inode;
	/* set once the backing file has been looked up, successfully or not */
	bool open_tried;
	/* set once loading failed (or yielded nothing) to avoid retrying */
	bool syms_load_failed;

	struct sym *syms;
	int syms_sz;
	int syms_cap;

	/*
	 * libbpf's struct btf is actually a pretty efficient
	 * "set of strings" data structure, so we create an
	 * empty one and use it to store symbol names.
	 */
	struct btf *btf;
};

struct map {
	uint64_t start_addr;
	uint64_t end_addr;
	uint64_t file_off;
	uint64_t dev_major;
	uint64_t dev_minor;
	uint64_t inode;
};

struct syms {
	struct dso *dsos;
	int dso_sz;
};

static bool is_file_backed(const char *mapname)
{
#define STARTS_WITH(mapname, prefix) \
	(!strncmp(mapname, prefix, sizeof(prefix) - 1))

	return mapname[0] && !(
		STARTS_WITH(mapname, "//anon") ||
		STARTS_WITH(mapname, "/dev/zero") ||
		STARTS_WITH(mapname, "/anon_hugepage") ||
		STARTS_WITH(mapname, "[stack") ||
		STARTS_WITH(mapname, "/SYSV") ||
		STARTS_WITH(mapname, "[heap]") ||
		STARTS_WITH(mapname, "[uprobes]") ||
		STARTS_WITH(mapname, "[vsyscall]"));
}

static bool is_perf_map(const char *path)
{
	return false;
}

static bool is_vdso(const char *path)
{
	return !strcmp(path, "[vdso]");
}

static bool is_uprobes(const char *path)
{
	return !strcmp(path, "[uprobes]");
}

/* BCC_SYM_DEBUG=1 prints why symbol resolution failed for a mapping. */
static bool sym_debug(void)
{
	static int cached = -1;

	if (cached < 0) {
		const char *s = getenv("BCC_SYM_DEBUG");

		cached = (s && s[0] && s[0] != '0') ? 1 : 0;
	}
	return cached == 1;
}

static const char *open_method_str(enum dso_open_method method)
{
	switch (method) {
	case DSO_OPEN_MAP_FILES:	return "map_files";
	case DSO_OPEN_PROC_ROOT:	return "proc-root";
	case DSO_OPEN_RAW_PATH:		return "raw-path";
	default:			return "failed";
	}
}

/* Needs CONFIG_CHECKPOINT_RESTORE + CAP_SYS_ADMIN; probe once. */
static bool map_files_available(void)
{
	static int cached = -1;

	if (cached < 0) {
		cached = access("/proc/self/map_files", X_OK) == 0 ? 1 : 0;
		if (!cached && sym_debug())
			fprintf(stderr,
				"sym: /proc/self/map_files unusable (%s), falling back to path based lookup\n",
				strerror(errno));
	}
	return cached == 1;
}

/* Only ever return a regular file; open() on a FIFO would block forever. */
static int open_regular_ro(const char *path)
{
	struct stat st;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		return -1;
	}
	return fd;
}

/*
 * Open the ELF that the target mapping was actually created from, in
 * order of decreasing trust:
 *  1. /proc/<tgid>/map_files/<start>-<end>: resolved by the kernel straight
 *     to vma->vm_file, immune to mount namespaces and unlink().
 *  2. /proc/<tgid>/root/<path>: looked up under the target's fs root, so at
 *     least the namespace is correct.
 *  3. the raw path: only correct for a non-containerised target.
 */
static int open_dso_fd(pid_t tgid, uint64_t start, uint64_t end,
		       const char *path, enum dso_open_method *method)
{
	char buf[PATH_MAX];
	int fd, n;

	*method = DSO_OPEN_FAILED;

	if (tgid > 0 && map_files_available()) {
		/*
		 * dname_to_vma_addr() rejects any zero padding, so the range
		 * must be printed in minimal form: "%x", never "%016lx".
		 */
		n = snprintf(buf, sizeof(buf),
			     "/proc/%d/map_files/%llx-%llx",
			     tgid, (unsigned long long)start,
			     (unsigned long long)end);
		if (n > 0 && n < (int)sizeof(buf)) {
			fd = open_regular_ro(buf);
			if (fd >= 0) {
				*method = DSO_OPEN_MAP_FILES;
				return fd;
			}
			if (sym_debug())
				fprintf(stderr, "sym: open %s failed: %s\n",
					buf, strerror(errno));
		}
	}

	if (tgid > 0 && path[0] == '/') {
		n = snprintf(buf, sizeof(buf), "/proc/%d/root%s", tgid, path);
		if (n > 0 && n < (int)sizeof(buf)) {
			fd = open_regular_ro(buf);
			if (fd >= 0) {
				*method = DSO_OPEN_PROC_ROOT;
				return fd;
			}
		}
	}

	fd = open_regular_ro(path);
	if (fd >= 0) {
		*method = DSO_OPEN_RAW_PATH;
		return fd;
	}
	return -1;
}

/* Upper bound on ELF fds held across all cached processes. */
#define DSO_FD_BUDGET	256

static int dso_fd_in_use;

static void dso__put_fd(struct dso *dso)
{
	if (dso->fd >= 0) {
		close(dso->fd);
		dso->fd = -1;
		dso_fd_in_use--;
	}
}

/* elf_begin() on a caller owned fd, without closing it on failure. */
static Elf *dso_elf_begin(int fd)
{
	Elf *e;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return NULL;
	e = elf_begin(fd, ELF_C_READ, NULL);
	if (!e)
		return NULL;
	if (elf_kind(e) != ELF_K_ELF) {
		elf_end(e);
		return NULL;
	}
	return e;
}

/*
 * Determine the ELF type and, for shared objects, the .text section
 * address/offset, reading everything from the already resolved fd.
 */
static int dso__read_elf_info(struct dso *dso, int fd)
{
	Elf_Scn *section = NULL;
	GElf_Shdr shdr;
	GElf_Ehdr ehdr;
	int err = -1;
	size_t stridx;
	char *name;
	Elf *e;

	e = dso_elf_begin(fd);
	if (!e)
		return -1;

	if (!gelf_getehdr(e, &ehdr))
		goto out;

	if (ehdr.e_type == ET_EXEC) {
		dso->type = EXEC;
		err = 0;
		goto out;
	}
	if (ehdr.e_type != ET_DYN)
		goto out;

	if (elf_getshdrstrndx(e, &stridx) < 0)
		goto out;

	while ((section = elf_nextscn(e, section)) != 0) {
		if (!gelf_getshdr(section, &shdr))
			continue;
		name = elf_strptr(e, stridx, shdr.sh_name);
		if (name && !strcmp(name, ".text")) {
			dso->sh_addr = (uint64_t)shdr.sh_addr;
			dso->sh_offset = (uint64_t)shdr.sh_offset;
			dso->type = DYN;
			err = 0;
			break;
		}
	}

out:
	elf_end(e);
	return err;
}

/* Register one executable mapping; only allocation failures are fatal. */
static int syms__add_dso(struct syms *syms, struct map *map, const char *name,
			 pid_t tgid)
{
	enum dso_open_method method;
	uint64_t dev, inode;
	struct dso *dso = NULL;
	int i, fd;
	void *tmp;

	dev = MKDEV(map->dev_major, map->dev_minor);
	inode = map->inode;

	/*
	 * dev+inode identifies the file itself even where the pathname
	 * does not; mappings without an inode ([vdso] etc.) key off name.
	 */
	for (i = 0; i < syms->dso_sz; i++) {
		struct dso *cand = &syms->dsos[i];

		if (inode) {
			if (cand->inode == inode && cand->dev == dev) {
				dso = cand;
				break;
			}
		} else if (!cand->inode && !strcmp(cand->name, name)) {
			dso = cand;
			break;
		}
	}

	if (!dso) {
		tmp = realloc(syms->dsos, (syms->dso_sz + 1) *
			      sizeof(*syms->dsos));
		if (!tmp)
			return -1;
		syms->dsos = tmp;
		dso = &syms->dsos[syms->dso_sz++];
		memset(dso, 0, sizeof(*dso));
		/* fd must be -1 before any early return can reach syms__free(). */
		dso->fd = -1;
		dso->type = UNKNOWN;
		dso->name = strdup(name);
		dso->btf = btf__new_empty();
		if (!dso->name || !dso->btf)
			return -1;
		dso->tgid = tgid;
		dso->loc_start = map->start_addr;
		dso->loc_end = map->end_addr;
		dso->dev = dev;
		dso->inode = inode;
	}

	tmp = realloc(dso->ranges, (dso->range_sz + 1) * sizeof(*dso->ranges));
	if (!tmp)
		return -1;
	dso->ranges = tmp;
	dso->ranges[dso->range_sz].start = map->start_addr;
	dso->ranges[dso->range_sz].end = map->end_addr;
	dso->ranges[dso->range_sz].file_off = map->file_off;
	dso->range_sz++;

	/* Already handled through one of its other mappings. */
	if (dso->open_tried || dso->type != UNKNOWN)
		return 0;

	if (is_vdso(name)) {
		dso->type = VDSO;
		return 0;
	}
	if (is_perf_map(name)) {
		dso->type = PERF_MAP;
		return 0;
	}

	/*
	 * The backing file is looked up at most once per dso; skip if
	 * already tried via another VMA of the same ELF.
	 */
	dso->open_tried = true;

	if (is_uprobes(name))
		return 0;

	fd = open_dso_fd(tgid, dso->loc_start, dso->loc_end, name, &method);
	if (fd < 0) {
		if (sym_debug())
			fprintf(stderr, "sym: %s: no backing file found\n",
				name);
		return 0;
	}
	dso->open_method = method;

	if (dso__read_elf_info(dso, fd) < 0) {
		dso->type = UNKNOWN;
		if (sym_debug())
			fprintf(stderr, "sym: %s: unusable ELF (via %s)\n",
				name, open_method_str(method));
		close(fd);
		return 0;
	}

	if (sym_debug())
		fprintf(stderr, "sym: %s: %s via %s (dev %" PRIx64 ":%" PRIx64
			" ino %" PRIu64 ")\n", name,
			dso->type == EXEC ? "ET_EXEC" : "ET_DYN",
			open_method_str(method), map->dev_major,
			map->dev_minor, inode);

	/* Hold the fd: the symbol table is read lazily, possibly after exit. */
	if (dso_fd_in_use < DSO_FD_BUDGET) {
		dso->fd = fd;
		dso_fd_in_use++;
	} else {
		close(fd);
	}
	return 0;
}

static struct dso *syms__find_dso(const struct syms *syms, unsigned long addr,
				  uint64_t *offset)
{
	struct load_range *range;
	struct dso *dso;
	int i, j;

	for (i = 0; i < syms->dso_sz; i++) {
		dso = &syms->dsos[i];
		for (j = 0; j < dso->range_sz; j++) {
			range = &dso->ranges[j];
			if (addr <= range->start || addr >= range->end)
				continue;
			if (dso->type == DYN || dso->type == VDSO) {
				/* Offset within the mmap */
				*offset = addr - range->start + range->file_off;
				/* Offset within the ELF for dyn symbol lookup */
				*offset += dso->sh_addr - dso->sh_offset;
			} else {
				*offset = addr;
			}

			return dso;
		}
	}

	return NULL;
}

static int dso__load_sym_table_from_perf_map(struct dso *dso)
{
	return -1;
}

static int dso__add_sym(struct dso *dso, const char *name, uint64_t start,
			uint64_t size)
{
	struct sym *sym;
	size_t new_cap;
	void *tmp;
	int off;

	off = btf__add_str(dso->btf, name);
	if (off < 0)
		return off;

	if (dso->syms_sz + 1 > dso->syms_cap) {
		new_cap = dso->syms_cap * 4 / 3;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(dso->syms, sizeof(*dso->syms) * new_cap);
		if (!tmp)
			return -1;
		dso->syms = tmp;
		dso->syms_cap = new_cap;
	}

	sym = &dso->syms[dso->syms_sz++];
	/* while constructing, re-use pointer as just a plain offset */
	sym->name = (void*)(unsigned long)off;
	sym->start = start;
	sym->size = size;
	sym->offset = 0;

	return 0;
}

static int sym_cmp(const void *p1, const void *p2)
{
	const struct sym *s1 = p1, *s2 = p2;

	if (s1->start == s2->start)
		return strcmp(s1->name, s2->name);
	return s1->start < s2->start ? -1 : 1;
}

static int dso__add_syms(struct dso *dso, Elf *e, Elf_Scn *section,
			 size_t stridx, size_t symsize)
{
	Elf_Data *data = NULL;

	/* A zero sh_entsize (attacker controlled) would cause SIGFPE below. */
	if (symsize == 0)
		return 0;

	while ((data = elf_getdata(section, data)) != 0) {
		size_t i, symcount = data->d_size / symsize;

		/* Truncated/inconsistent table; keep symbols parsed so far. */
		if (data->d_size % symsize)
			break;

		for (i = 0; i < symcount; ++i) {
			const char *name;
			GElf_Sym sym;

			if (!gelf_getsym(data, (int)i, &sym))
				continue;
			if (!(name = elf_strptr(e, stridx, sym.st_name)))
				continue;
			if (name[0] == '\0')
				continue;

			if (sym.st_value == 0)
				continue;

			if (dso__add_sym(dso, name, sym.st_value, sym.st_size))
				goto err_out;
		}
	}

	return 0;

err_out:
	return -1;
}

static void dso__drop_syms(struct dso *dso)
{
	free(dso->syms);
	dso->syms = NULL;
	dso->syms_sz = 0;
	dso->syms_cap = 0;
}

static void dso__free_fields(struct dso *dso)
{
	if (!dso)
		return;

	dso__put_fd(dso);
	free(dso->name);
	free(dso->ranges);
	free(dso->syms);
	btf__free(dso->btf);

	/* Clear relevant fields in dso to avoid dangling pointers. */
	dso->name = NULL;
	dso->ranges = NULL;
	dso->range_sz = 0;
	dso->syms = NULL;
	dso->btf = NULL;

	/* Zero out size/capacity to avoid stale bounds/alloc decisions. */
	dso->syms_sz = 0;
	dso->syms_cap = 0;
	dso->type = UNKNOWN;
	dso->sh_addr = 0;
	dso->sh_offset = 0;
}

/* Reads from a caller owned fd; the fd is left open. */
static int dso__load_sym_table_from_elf(struct dso *dso, int fd)
{
	Elf_Scn *section = NULL;
	Elf *e;
	int i;

	e = dso_elf_begin(fd);
	if (!e)
		return -1;

	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;

		if (!gelf_getshdr(section, &header))
			continue;

		if (header.sh_type != SHT_SYMTAB &&
		    header.sh_type != SHT_DYNSYM)
			continue;

		if (dso__add_syms(dso, e, section, header.sh_link,
				  header.sh_entsize))
			goto err_out;
	}

	/* now when strings are finalized, adjust pointers properly */
	for (i = 0; i < dso->syms_sz; i++)
		dso->syms[i].name =
			btf__name_by_offset(dso->btf,
					    (unsigned long)dso->syms[i].name);

	qsort(dso->syms, dso->syms_sz, sizeof(*dso->syms), sym_cmp);

	elf_end(e);
	return 0;

err_out:
	/* Keep the dso itself intact; only the half built symbol table goes away. */
	dso__drop_syms(dso);
	elf_end(e);
	return -1;
}

static int create_tmp_vdso_image(struct dso *dso)
{
	uint64_t start_addr = 0, end_addr = 0;
	char line[PATH_MAX + 128];
	long pid = getpid();
	char buf[PATH_MAX];
	void *image = NULL;
	bool found = false;
	char tmpfile[128];
	int ret, fd = -1;
	uint64_t sz;
	char *name;
	FILE *f;

	snprintf(tmpfile, sizeof(tmpfile), "/proc/%ld/maps", pid);
	f = fopen(tmpfile, "r");
	if (!f)
		return -1;

	/* Width limited like syms__load_maps(); see there for why. */
	while (fgets(line, sizeof(line), f)) {
		ret = sscanf(line, "%llx-%llx %*s %*x %*x:%*x %*u%4095[^\n]",
			     (long long*)&start_addr, (long long*)&end_addr,
			     buf);
		if (ret != 3)
			continue;

		name = buf;
		while (isspace(*name))
			name++;
		if (is_vdso(name)) {
			found = true;
			break;
		}
	}

	/* Bail out if [vdso] was never found, instead of using stale start/end. */
	if (!found)
		goto err_out;

	sz = end_addr - start_addr;
	image = malloc(sz);
	if (!image)
		goto err_out;
	memcpy(image, (void *)start_addr, sz);

	snprintf(tmpfile, sizeof(tmpfile),
		 "/tmp/libbpf_%ld_vdso_image_XXXXXX", pid);
	fd = mkostemp(tmpfile, O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "failed to create temp file: %s\n",
			strerror(errno));
		goto err_out;
	}
	/* Unlink the file to avoid leaking */
	if (unlink(tmpfile) == -1)
		fprintf(stderr, "failed to unlink %s: %s\n", tmpfile,
			strerror(errno));
	if (write(fd, image, sz) == -1) {
		fprintf(stderr, "failed to write to vDSO image: %s\n",
			strerror(errno));
		close(fd);
		fd = -1;
		goto err_out;
	}

err_out:
	fclose(f);
	free(image);
	return fd;
}

static int dso__load_sym_table_from_vdso_image(struct dso *dso)
{
	int fd = create_tmp_vdso_image(dso);
	int err;

	if (fd < 0)
		return -1;
	err = dso__load_sym_table_from_elf(dso, fd);
	close(fd);
	return err;
}

static int dso__load_sym_table(struct dso *dso)
{
	enum dso_open_method method;
	int fd, err;

	if (dso->type == UNKNOWN)
		return -1;
	if (dso->type == PERF_MAP)
		return dso__load_sym_table_from_perf_map(dso);
	if (dso->type == VDSO)
		return dso__load_sym_table_from_vdso_image(dso);
	if (dso->type != EXEC && dso->type != DYN)
		return -1;

	if (dso->fd >= 0) {
		err = dso__load_sym_table_from_elf(dso, dso->fd);
		/* symbols are in memory now, the file is no longer needed */
		dso__put_fd(dso);
		return err;
	}

	/* fd budget was exhausted earlier; re-locate (may fail if exited). */
	fd = open_dso_fd(dso->tgid, dso->loc_start, dso->loc_end, dso->name,
			 &method);
	if (fd < 0) {
		if (sym_debug())
			fprintf(stderr, "sym: %s: re-open failed: %s\n",
				dso->name, strerror(errno));
		return -1;
	}
	err = dso__load_sym_table_from_elf(dso, fd);
	close(fd);
	return err;
}

/*
 * The returned sym points into the dso's shared symbol table; valid only
 * until the next lookup on the same dso.
 */
static struct sym *dso__find_sym(struct dso *dso, uint64_t offset)
{
	unsigned long sym_addr;
	int start, end, mid;

	if (!dso->syms) {
		/* Don't retry per event for a stripped/unreadable dso. */
		if (dso->syms_load_failed)
			return NULL;
		if (dso__load_sym_table(dso) || !dso->syms_sz) {
			dso->syms_load_failed = true;
			return NULL;
		}
	}

	start = 0;
	end = dso->syms_sz - 1;

	/* find largest sym_addr <= addr using binary search */
	while (start < end) {
		mid = start + (end - start + 1) / 2;
		sym_addr = dso->syms[mid].start;

		if (sym_addr <= offset)
			start = mid;
		else
			end = mid - 1;
	}

	if (start == end && dso->syms[start].start <= offset &&
	    offset < dso->syms[start].start + dso->syms[start].size) {
		(dso->syms[start]).offset = offset - dso->syms[start].start;
		return &dso->syms[start];
	}
	return NULL;
}

/*
 * tgid > 0 resolves mappings through /proc/<tgid>/; -1 (an external maps
 * dump) restricts us to plain path lookups.
 */
static struct syms *syms__load_maps(const char *fname, pid_t tgid)
{
	char line[PATH_MAX + 128], buf[PATH_MAX], perm[5];
	struct syms *syms;
	struct map map;
	char *name;
	FILE *f;
	int ret;

	f = fopen(fname, "r");
	if (!f)
		return NULL;

	syms = calloc(1, sizeof(*syms));
	if (!syms)
		goto err_out;

	/*
	 * Read line by line with width limited sscanf(): the pathname from
	 * d_path() is not bounded by PATH_MAX, so an unbounded conversion
	 * could overflow buf.
	 */
	while (fgets(line, sizeof(line), f)) {
		ret = sscanf(line,
			     "%llx-%llx %4s %llx %llx:%llx %llu%4095[^\n]",
			     (long long*)&map.start_addr,
			     (long long*)&map.end_addr, perm,
			     (long long*)&map.file_off,
			     (long long*)&map.dev_major,
			     (long long*)&map.dev_minor,
			     (long long*)&map.inode, buf);
		/* Anonymous mappings and malformed lines fall short of 8 fields. */
		if (ret != 8)
			continue;

		if (perm[2] != 'x')
			continue;

		name = buf;
		while (isspace(*name))
			name++;
		if (!is_file_backed(name))
			continue;

		if (syms__add_dso(syms, &map, name, tgid))
			goto err_out;
	}

	fclose(f);
	return syms;

err_out:
	syms__free(syms);
	fclose(f);
	return NULL;
}

struct syms *syms__load_file(const char *fname)
{
	return syms__load_maps(fname, -1);
}

struct syms *syms__load_pid(pid_t tgid)
{
	char fname[128];

	snprintf(fname, sizeof(fname), "/proc/%ld/maps", (long)tgid);
	return syms__load_maps(fname, tgid);
}

void syms__free(struct syms *syms)
{
	int i;

	if (!syms)
		return;

	for (i = 0; i < syms->dso_sz; i++)
		dso__free_fields(&syms->dsos[i]);
	free(syms->dsos);
	free(syms);
}

const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr)
{
	struct dso *dso;
	uint64_t offset;

	dso = syms__find_dso(syms, addr, &offset);
	if (!dso)
		return NULL;
	return dso__find_sym(dso, offset);
}

int syms__map_addr_dso(const struct syms *syms, unsigned long addr,
		       struct sym_info *sinfo)
{
	struct dso *dso;
	struct sym *sym;
	uint64_t offset;

	memset(sinfo, 0x0, sizeof(struct sym_info));

	dso = syms__find_dso(syms, addr, &offset);
	if (!dso)
		return -1;

	sinfo->dso_name = dso->name;
	sinfo->dso_offset = offset;

	sym = dso__find_sym(dso, offset);
	if (sym) {
		sinfo->sym_name = sym->name;
		sinfo->sym_offset = sym->offset;
	}

	return 0;
}

struct syms_cache {
	struct {
		struct syms *syms;
		int tgid;
	} *data;
	int nr;
};

struct syms_cache *syms_cache__new(int nr)
{
	struct syms_cache *syms_cache;

	syms_cache = calloc(1, sizeof(*syms_cache));
	if (!syms_cache)
		return NULL;
	if (nr > 0)
		syms_cache->data = calloc(nr, sizeof(*syms_cache->data));
	return syms_cache;
}

void syms_cache__free(struct syms_cache *syms_cache)
{
	int i;

	if (!syms_cache)
		return;

	for (i = 0; i < syms_cache->nr; i++)
		syms__free(syms_cache->data[i].syms);
	free(syms_cache->data);
	free(syms_cache);
}

struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid)
{
	void *tmp;
	int i;

	for (i = 0; i < syms_cache->nr; i++) {
		if (syms_cache->data[i].tgid == tgid)
			return syms_cache->data[i].syms;
	}

	tmp = realloc(syms_cache->data, (syms_cache->nr + 1) *
		      sizeof(*syms_cache->data));
	if (!tmp)
		return NULL;
	syms_cache->data = tmp;
	syms_cache->data[syms_cache->nr].syms = syms__load_pid(tgid);
	syms_cache->data[syms_cache->nr].tgid = tgid;
	return syms_cache->data[syms_cache->nr++].syms;
}

struct partitions {
	struct partition *items;
	int sz;
};

static int partitions__add_partition(struct partitions *partitions,
				     const char *name, unsigned int dev)
{
	struct partition *partition;
	void *tmp;

	tmp = realloc(partitions->items, (partitions->sz + 1) *
		sizeof(*partitions->items));
	if (!tmp)
		return -1;
	partitions->items = tmp;
	partition = &partitions->items[partitions->sz];
	partition->name = strdup(name);
	partition->dev = dev;
	partitions->sz++;

	return 0;
}

struct partitions *partitions__load(void)
{
	char part_name[DISK_NAME_LEN];
	unsigned int devmaj, devmin;
	unsigned long long nop;
	struct partitions *partitions;
	char buf[64];
	FILE *f;

	f = fopen("/proc/partitions", "r");
	if (!f)
		return NULL;

	partitions = calloc(1, sizeof(*partitions));
	if (!partitions)
		goto err_out;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		/* skip heading */
		if (buf[0] != ' ' || buf[0] == '\n')
			continue;
		if (sscanf(buf, "%u %u %llu %s", &devmaj, &devmin, &nop,
				part_name) != 4)
			goto err_out;
		if (partitions__add_partition(partitions, part_name,
						MKDEV(devmaj, devmin)))
			goto err_out;
	}

	fclose(f);
	return partitions;

err_out:
	partitions__free(partitions);
	fclose(f);
	return NULL;
}

void partitions__free(struct partitions *partitions)
{
	int i;

	if (!partitions)
		return;

	for (i = 0; i < partitions->sz; i++)
		free(partitions->items[i].name);
	free(partitions->items);
	free(partitions);
}

const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev)
{
	int i;

	for (i = 0; i < partitions->sz; i++) {
		if (partitions->items[i].dev == dev)
			return &partitions->items[i];
	}

	return NULL;
}

const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name)
{
	int i;

	for (i = 0; i < partitions->sz; i++) {
		if (strcmp(partitions->items[i].name, name) == 0)
			return &partitions->items[i];
	}

	return NULL;
}

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
		idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++) {
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
		print_stars(val, val_max, stars);
		printf("|\n");
	}
}

void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
		       unsigned int step, const char *val_type)
{
	int i, stars_max = 40, idx_min = -1, idx_max = -1;
	unsigned int val, val_max = 0;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0) {
			idx_max = i;
			if (idx_min < 0)
				idx_min = i;
		}
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("     %-13s : count     distribution\n", val_type);
	for (i = idx_min; i <= idx_max; i++) {
		val = vals[i];
		if (!val)
			continue;
		printf("        %-10d : %-8d |", base + i * step, val);
		print_stars(val, val_max, stars_max);
		printf("|\n");
	}
}

unsigned long long get_ktime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

bool is_kernel_module(const char *name)
{
	bool found = false;
	char buf[64];
	FILE *f;

	f = fopen("/proc/modules", "r");
	if (!f)
		return false;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (sscanf(buf, "%s %*s\n", buf) != 1)
			break;
		if (!strcmp(buf, name)) {
			found = true;
			break;
		}
	}

	fclose(f);
	return found;
}

static bool fentry_try_attach(int id)
{
	int prog_fd, attach_fd;
	char error[4096];
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
			.expected_attach_type = BPF_TRACE_FENTRY,
			.attach_btf_id = id,
			.log_buf = error,
			.log_size = sizeof(error),
	);

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
			sizeof(insns) / sizeof(struct bpf_insn), &opts);
	if (prog_fd < 0)
		return false;

	attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
	if (attach_fd >= 0)
		close(attach_fd);

	close(prog_fd);
	return attach_fd >= 0;
}

bool fentry_can_attach(const char *name, const char *mod)
{
	struct btf *btf, *vmlinux_btf, *module_btf = NULL;
	int err, id;

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err)
		return false;

	btf = vmlinux_btf;

	if (mod) {
		module_btf = btf__load_module_btf(mod, vmlinux_btf);
		err = libbpf_get_error(module_btf);
		if (!err)
			btf = module_btf;
	}

	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

	btf__free(module_btf);
	btf__free(vmlinux_btf);
	return id > 0 && fentry_try_attach(id);
}

#define DEBUGFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

static bool use_debugfs(void)
{
	static int has_debugfs = -1;

	if (has_debugfs < 0)
		has_debugfs = faccessat(AT_FDCWD, DEBUGFS, F_OK, AT_EACCESS) == 0;

	return has_debugfs == 1;
}

static const char *tracefs_path(void)
{
	return use_debugfs() ? DEBUGFS : TRACEFS;
}

static const char *tracefs_available_filter_functions(void)
{
	return use_debugfs() ? DEBUGFS"/available_filter_functions" :
			       TRACEFS"/available_filter_functions";
}

bool kprobe_exists(const char *name)
{
	char addr_range[256];
	char sym_name[256];
	FILE *f;
	int ret;

	f = fopen("/sys/kernel/debug/kprobes/blacklist", "r");
	if (!f)
		goto avail_filter;

	while (true) {
		ret = fscanf(f, "%s %s%*[^\n]\n", addr_range, sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 2) {
			fprintf(stderr, "failed to read symbol from kprobe blacklist\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return false;
		}
	}
	fclose(f);

avail_filter:
	f = fopen(tracefs_available_filter_functions(), "r");
	if (!f)
		goto slow_path;

	while (true) {
		ret = fscanf(f, "%s%*[^\n]\n", sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 1) {
			fprintf(stderr, "failed to read symbol from available_filter_functions\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return true;
		}
	}

	fclose(f);
	return false;

slow_path:
	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return false;

	while (true) {
		ret = fscanf(f, "%*x %*c %s%*[^\n]\n", sym_name);
		if (ret == EOF && feof(f))
			break;
		if (ret != 1) {
			fprintf(stderr, "failed to read symbol from kallsyms\n");
			break;
		}
		if (!strcmp(name, sym_name)) {
			fclose(f);
			return true;
		}
	}

	fclose(f);
	return false;
}

bool tracepoint_exists(const char *category, const char *event)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/events/%s/%s/format", tracefs_path(), category, event);
	if (!access(path, F_OK))
		return true;
	return false;
}

bool vmlinux_btf_exists(void)
{
	struct btf *btf;
	int err;

	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err)
		return false;

	btf__free(btf);
	return true;
}

bool module_btf_exists(const char *mod)
{
	char sysfs_mod[80];

	if (mod) {
		snprintf(sysfs_mod, sizeof(sysfs_mod), "/sys/kernel/btf/%s", mod);
		if (!access(sysfs_mod, R_OK))
			return true;
	}
	return false;
}

bool probe_tp_btf(const char *name)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .expected_attach_type = BPF_TRACE_RAW_TP);
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	int fd, insn_cnt = sizeof(insns) / sizeof(struct bpf_insn);

	opts.attach_btf_id = libbpf_find_vmlinux_btf_id(name, BPF_TRACE_RAW_TP);
	fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, insn_cnt, &opts);
	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

bool probe_ringbuf()
{
	int map_fd;

	map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, getpagesize(), NULL);
	if (map_fd < 0)
		return false;

	close(map_fd);
	return true;
}

bool probe_bpf_ns_current_pid_tgid(void)
{
	int fd, insn_cnt;
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = 3, .src_reg = BPF_REG_10 },
		{ .code = BPF_ALU64 | BPF_ADD | BPF_K, .dst_reg = 3, .imm = -8 },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 1, .imm = 0 },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 2, .imm = 0 },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 4, .imm = 8 },
		{ .code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_get_ns_current_pid_tgid },
		{ .code = BPF_JMP | BPF_EXIT },
	};

	insn_cnt = sizeof(insns) / sizeof(insns[0]);

	fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, NULL, "GPL", insns, insn_cnt, NULL);
	if (fd >= 0)
		close(fd);

	return fd >= 0;
}

int split_convert(char *s, const char* delim, void *elems, size_t elems_size,
		  size_t elem_size, convert_fn_t convert)
{
	char *token;
	int ret;
	char *pos = (char *)elems;

	if (!s || !delim || !elems)
		return -EINVAL;

	token = strtok(s, delim);
	while (token) {
		if (pos + elem_size > (char*)elems + elems_size)
			return -ENOBUFS;

		ret = convert(token, pos);
		if (ret)
			return -ret;

		pos += elem_size;
		token = strtok(NULL, delim);
	}

	return 0;
}

int str_to_int(const char *src, void *dest)
{
	errno = 0;
	*(int*)dest = strtol(src, NULL, 10);

	return errno;
}

int str_to_long(const char *src, void *dest)
{
	errno = 0;
	*(long*)dest = strtol(src, NULL, 10);

	return errno;
}

int str_loadavg(char *buf, size_t buf_len)
{
	int n, err = 0;
	char avg[64] = {0};
	FILE *f;

	if (!buf || buf_len == 0)
		return -EINVAL;

	f = fopen("/proc/loadavg", "r");
	if (!f)
		return -errno;

	n = fread(avg, 1, sizeof(avg) - 1, f);
	if (!n) {
		err = -errno;
		goto cleanup;
	}

	n = snprintf(buf, buf_len, "loadavg: %s", avg);

	if (n >= buf_len)
		err = -ERANGE;

cleanup:
	fclose(f);
	return err ?: n;
}

int str_timestamp(const char *format, char *buf, size_t buf_len)
{
	time_t t;
	struct tm *tm;

	if (!format || !buf || buf_len == 0)
		return -EINVAL;

	time(&t);
	tm = localtime(&t);
	if (!tm)
		return -errno;
	return strftime(buf, buf_len, format, tm);
}
