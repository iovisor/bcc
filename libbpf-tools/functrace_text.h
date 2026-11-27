/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * functrace_text.h — top-down block text output
 *
 * Internal to functrace; do NOT include from trace_helpers.h/c.
 */

#ifndef __FUNCTRACE_TEXT_H
#define __FUNCTRACE_TEXT_H

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "functrace.h"

/* ── Safety limits ──────────────────────────────────────────────────── */

#define TEXT_BUF_MAX_SPANS   512   /* max spans per trace buffer */
#define TEXT_BUF_MAX_TRACES  256   /* max concurrent incomplete traces */

/* ── Data structures ─────────────────────────────────────────────────── */

/**
 * struct text_span_entry - One span stored while buffering a trace.
 */
struct text_span_entry {
	char     name[FUNC_NAME_LEN];
	uint64_t start_ns;   /* bpf_ktime_get_ns() at entry (CLOCK_MONOTONIC) */
	uint64_t end_ns;
	int      depth;      /* shadow stack depth (0 = root) */
};

/**
 * struct text_trace_buf - Per-(tid,trace_id_lo) accumulator for top-down mode.
 */
struct text_trace_buf {
	bool     active;
	uint32_t pid;
	uint32_t tid;
	uint64_t trace_id_lo;
	uint64_t root_start_ns;
	uint64_t root_end_ns;
	int      span_count;
	struct text_span_entry spans[TEXT_BUF_MAX_SPANS];
};

/* ── Globals (defined in functrace_text.c) ───────────────────────────── */

/** Program start monotonic ns — captured by text_output_init(). */
extern uint64_t g_text_prog_start_ns;

/** Static buffer pool. */
extern struct text_trace_buf g_text_bufs[TEXT_BUF_MAX_TRACES];

/* ── Lifecycle ───────────────────────────────────────────────────────── */

/**
 * text_output_init - Initialise the text output subsystem.
 *
 * Must be called once before any events are processed.
 * Captures g_text_prog_start_ns and zeroes the buffer pool.
 */
void text_output_init(void);

/* ── Buffer management ───────────────────────────────────────────────── */

struct text_trace_buf *trace_buf_find(uint32_t tid, uint64_t trace_id_lo);
struct text_trace_buf *trace_buf_create(uint32_t tid, uint64_t trace_id_lo);
struct text_trace_buf *trace_buf_find_or_create(uint32_t tid,
						uint64_t trace_id_lo);
struct text_trace_buf *trace_buf_evict_oldest(void);

/**
 * trace_buf_add_span - Append a span to a buffer.
 *
 * Returns true if added, false if the buffer is full (span dropped).
 * Caller is responsible for emitting a stderr warning on false return.
 */
bool trace_buf_add_span(struct text_trace_buf *buf,
			const char *name,
			uint64_t start_ns, uint64_t end_ns, int depth);

/* ── Output functions ────────────────────────────────────────────────── */

/**
 * text_trace_flush - Sort spans by start_ns and print a top-down block.
 *
 * Does NOT modify buf->active — caller must free the slot afterwards.
 */
void text_trace_flush(struct text_trace_buf *buf, FILE *fp);

/**
 * text_handle_span - Main entry point called from handle_event().
 */
void text_handle_span(const struct functrace_event *e,
		      const char *func_name,
		      FILE *fp);

#endif /* __FUNCTRACE_TEXT_H */
