// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * functrace_text.c  Text output implementation for functrace.
 *
 * Buffer spans per (tid, trace_id_lo); flush on root-func exit.
 */

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "functrace.h"
#include "functrace_text.h"

/* ── Globals ─────────────────────────────────────────────────────────── */

uint64_t g_text_prog_start_ns;
struct text_trace_buf g_text_bufs[TEXT_BUF_MAX_TRACES];

/* ── Lifecycle ─────────────────────────────────────────────────────────── */

void text_output_init(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	g_text_prog_start_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
			       (uint64_t)ts.tv_nsec;
	memset(g_text_bufs, 0, sizeof(g_text_bufs));
}

/* ── Buffer management ───────────────────────────────────────────────── */

struct text_trace_buf *trace_buf_find(uint32_t tid, uint64_t trace_id_lo)
{
	int i;

	for (i = 0; i < TEXT_BUF_MAX_TRACES; i++) {
		if (g_text_bufs[i].active &&
		    g_text_bufs[i].tid == tid &&
		    g_text_bufs[i].trace_id_lo == trace_id_lo)
			return &g_text_bufs[i];
	}
	return NULL;
}

struct text_trace_buf *trace_buf_create(uint32_t tid, uint64_t trace_id_lo)
{
	int i;

	for (i = 0; i < TEXT_BUF_MAX_TRACES; i++) {
		if (!g_text_bufs[i].active) {
			memset(&g_text_bufs[i], 0, sizeof(g_text_bufs[i]));
			g_text_bufs[i].active       = true;
			g_text_bufs[i].tid          = tid;
			g_text_bufs[i].trace_id_lo  = trace_id_lo;
			return &g_text_bufs[i];
		}
	}
	return NULL;  /* no free slot */
}

struct text_trace_buf *trace_buf_find_or_create(uint32_t tid,
						uint64_t trace_id_lo)
{
	struct text_trace_buf *buf = trace_buf_find(tid, trace_id_lo);

	if (buf)
		return buf;
	return trace_buf_create(tid, trace_id_lo);
}

struct text_trace_buf *trace_buf_evict_oldest(void)
{
	struct text_trace_buf *oldest = NULL;
	uint64_t oldest_ns = UINT64_MAX;
	int i;

	for (i = 0; i < TEXT_BUF_MAX_TRACES; i++) {
		uint64_t ref;

		if (!g_text_bufs[i].active)
			continue;
		/* Use first accumulated span's start_ns as the age proxy */
		ref = (g_text_bufs[i].span_count > 0)
			? g_text_bufs[i].spans[0].start_ns
			: g_text_bufs[i].root_start_ns;
		if (ref < oldest_ns) {
			oldest_ns = ref;
			oldest    = &g_text_bufs[i];
		}
	}
	return oldest;
}

bool trace_buf_add_span(struct text_trace_buf *buf,
			const char *name,
			uint64_t start_ns, uint64_t end_ns, int depth)
{
	struct text_span_entry *s;

	if (buf->span_count >= TEXT_BUF_MAX_SPANS)
		return false;

	s = &buf->spans[buf->span_count++];
	strncpy(s->name, name, FUNC_NAME_LEN - 1);
	s->name[FUNC_NAME_LEN - 1] = '\0';
	s->start_ns = start_ns;
	s->end_ns   = end_ns;
	s->depth    = depth;
	return true;
}

/* ── Top-down flush ──────────────────────────────────────────────────── */

static int cmp_start_ns(const void *a, const void *b)
{
	const struct text_span_entry *sa = (const struct text_span_entry *)a;
	const struct text_span_entry *sb = (const struct text_span_entry *)b;

	if (sa->start_ns < sb->start_ns)
		return -1;
	if (sa->start_ns > sb->start_ns)
		return 1;
	return 0;
}

void text_trace_flush(struct text_trace_buf *buf, FILE *fp)
{
	uint64_t root_start, root_end;
	double elapsed_s, total_ms;
	int i;

	if (!buf || buf->span_count == 0)
		return;

	/* Sort spans by start_ns ascending — restores top-down (call) order */
	qsort(buf->spans, buf->span_count, sizeof(buf->spans[0]), cmp_start_ns);

	/*
	 * Determine root window.  For a forced-eviction flush the root span
	 * may not have arrived yet; fall back to first/last accumulated span.
	 */
	root_start = buf->root_start_ns
		? buf->root_start_ns
		: buf->spans[0].start_ns;
	root_end   = buf->root_end_ns
		? buf->root_end_ns
		: buf->spans[buf->span_count - 1].end_ns;

	/* Block header */
	elapsed_s = (double)(root_start - g_text_prog_start_ns) / 1e9;
	total_ms  = (double)(root_end   - root_start) / 1e6;
	fprintf(fp,
		"[trace %04llx | pid=%u tid=%u | start=+%.3fs | total=%.2fms]\n",
		(unsigned long long)(buf->trace_id_lo & 0xFFFF),
		buf->pid, buf->tid,
		elapsed_s, total_ms);

	/* Span lines */
	for (i = 0; i < buf->span_count; i++) {
		struct text_span_entry *s = &buf->spans[i];
		double lat_ms = (double)(s->end_ns - s->start_ns) / 1e6;
		int    indent = s->depth * 2;

		if (s->depth == 0) {
			fprintf(fp, "%-40s %8.2fms\n", s->name, lat_ms);
		} else {
			int name_w = 38 - indent;

			if (name_w < 8)
				name_w = 8;
			/*
			 * "└─ " is 3 display columns but 7 UTF-8 bytes.
			 * We use display-column width for indent math and
			 * accept minor byte-level misalignment in the
			 * name field — terminals render it correctly.
			 */
			fprintf(fp, "%*s└─ %-*s %8.2fms\n",
				indent, "",
				name_w, s->name,
				lat_ms);
		}
	}

	/* Block separator blank line */
	fprintf(fp, "\n");
	fflush(fp);
	/* NOTE: does NOT modify buf->active — caller frees the slot */
}

/* ── Main entry: text_handle_span ────────────────────────────────────── */

void text_handle_span(const struct functrace_event *e,
		      const char *func_name,
		      FILE *fp)
{
	uint32_t tid      = e->tid;
	uint64_t trace_id = e->trace_id_lo;
	struct text_trace_buf *buf;

	if (e->is_root) {
		/*
		 * Root-func exit: get-or-create buffer, set root window,
		 * add root span, flush, return slot to pool.
		 */
		buf = trace_buf_find(tid, trace_id);
		if (!buf)
			buf = trace_buf_create(tid, trace_id);

		if (!buf) {
			/*
			 * All slots taken even for root; evict oldest to
			 * make room.
			 */
			struct text_trace_buf *oldest = trace_buf_evict_oldest();

			if (oldest) {
				fprintf(stderr,
					"warn: trace buffer limit reached, "
					"force-flushing trace %04llx\n",
					(unsigned long long)(oldest->trace_id_lo & 0xFFFF));
				text_trace_flush(oldest, fp);
				oldest->active = false;
			}
			buf = trace_buf_create(tid, trace_id);
			if (!buf) {
				fprintf(stderr,
					"warn: cannot allocate text buffer "
					"for trace %04llx\n",
					(unsigned long long)(trace_id & 0xFFFF));
				return;
			}
		}

		buf->pid           = e->pid;
		buf->tid           = e->tid;
		buf->trace_id_lo   = e->trace_id_lo;
		buf->root_start_ns = e->start_ns;
		buf->root_end_ns   = e->end_ns;

		if (!trace_buf_add_span(buf, func_name,
					e->start_ns, e->end_ns, 0)) {
			fprintf(stderr,
				"warn: trace %04llx"
				" span limit reached, dropping %s\n",
				(unsigned long long)(e->trace_id_lo & 0xFFFF),
				func_name);
		}

		text_trace_flush(buf, fp);
		buf->active = false;   /* return slot to pool */

	} else {
		/*
		 * Child span exit: buffer it until root arrives.
		 */
		buf = trace_buf_find_or_create(tid, trace_id);

		if (!buf) {
			/* MAX_TRACES exceeded: evict oldest */
			struct text_trace_buf *oldest = trace_buf_evict_oldest();

			if (oldest) {
				fprintf(stderr,
					"warn: trace buffer limit reached, "
					"force-flushing trace %04llx\n",
					(unsigned long long)(oldest->trace_id_lo & 0xFFFF));
				text_trace_flush(oldest, fp);
				oldest->active = false;
			}
			buf = trace_buf_create(tid, trace_id);
			if (!buf)
				return;  /* should not happen after eviction */
		}

		/* Record pid on first child event if not set yet */
		if (!buf->pid)
			buf->pid = e->pid;

		if (!trace_buf_add_span(buf, func_name,
					e->start_ns, e->end_ns,
					(int)e->call_depth)) {
			fprintf(stderr,
				"warn: trace %04llx"
				" span limit reached, dropping %s\n",
				(unsigned long long)(e->trace_id_lo & 0xFFFF),
				func_name);
		}
	}
}
