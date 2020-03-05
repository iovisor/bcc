/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "trace_helpers.h"

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
