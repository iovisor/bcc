/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "trace_helpers.h"

#define MAX_SYMS 300000

static int ksyms__insert_symbol(struct ksyms *ksyms, long addr,
				const char *name)
{
	struct ksym *ksym = &ksyms->syms[ksyms->syms_cnt++];
	size_t len = strlen(name) + 1;

	ksym->name = malloc(len);
	if (!ksym->name)
		return -1;

	memcpy((void*)ksym->name, name, len);
	ksym->addr = addr;
	return 0;
}

static struct ksyms *ksyms__new(void)
{
	struct ksyms *ksyms = malloc(sizeof(*ksyms));

	if (!ksyms)
		return NULL;

	ksyms->syms_cnt = 0;
	ksyms->syms = malloc(MAX_SYMS * sizeof(struct ksym));
	if (!ksyms->syms)
		return NULL;
	return ksyms;
}

static int ksym_cmp(const void *p1, const void *p2)
{
	long cmp = ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;

	if (cmp < 0)
		return -1;
	else if (cmp > 0)
		return 1;
	else
		return 0;
}

static int hex2long(const char *ptr, long *long_val)
{
	char *p;

	*long_val = strtoul(ptr, &p, 16);
	return p - ptr;
}

struct ksyms *ksyms__load(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	const char *symbol_name;
	struct ksyms *ksyms;
	char *line = NULL;
	long symbol_addr;
	int line_len;
	int parsed;
	size_t n;
	int err;

	if (!f)
		return NULL;

	ksyms = ksyms__new();
	if (!ksyms)
		goto cleanup;

	while (!feof(f)) {
		line_len = getline(&line, &n, f);
		if (line_len < 0 || !line)
			break;

		line[--line_len] = '\0'; /* \n */

		parsed = hex2long(line, &symbol_addr);

		/* Skip the line if we failed to parse the address. */
		if (!parsed)
			continue;

		parsed++;
		if (parsed + 2 >= line_len)
			continue;

		parsed += 2;	/* ignore symbol type */
		symbol_name = line + parsed;
		parsed = line_len - parsed;

		err = ksyms__insert_symbol(ksyms, symbol_addr, symbol_name);
		if (err)
			goto cleanup;
	}

	qsort(ksyms->syms, ksyms->syms_cnt, sizeof(struct ksym), ksym_cmp);
	return ksyms;

cleanup:
	free(line);
	fclose(f);
	return NULL;
}

void ksyms__free(struct ksyms *ksyms)
{
	int i;

	if (!ksyms)
		return;

	for (i = 0; i < ksyms->syms_cnt; i++) {
		free((void*)ksyms->syms[i].name);
	}
	free(ksyms);
}

const struct ksym *ksyms__map_addr(const struct ksyms *ksyms, long addr)
{
	int start = 0, end = ksyms->syms_cnt;
	long result;

	/* kallsyms not loaded. return NULL */
	if (ksyms->syms_cnt == 0)
		return NULL;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = addr - ksyms->syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &ksyms->syms[mid];
	}

	if (start >= 1 && ksyms->syms[start - 1].addr < addr &&
	    addr < ksyms->syms[start].addr)
		/* valid ksym */
		return &ksyms->syms[start - 1];

	return NULL;
}

const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name)
{
	int i;

	for (i = 0; i < ksyms->syms_cnt; i++) {
		if (strcmp(ksyms->syms[i].name, name) == 0)
			return &ksyms->syms[i];
	}

	return NULL;
}
