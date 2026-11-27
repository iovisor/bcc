/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define NSEC_PER_SEC		1000000000ULL

struct ksym {
	const char *name;
	unsigned long addr;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name);

struct sym {
	const char *name;
	unsigned long start;
	unsigned long size;
	unsigned long offset;
};

struct sym_info {
	const char *dso_name;
	unsigned long dso_offset;
	const char *sym_name;
	unsigned long sym_offset;
};

struct syms;

struct syms *syms__load_pid(int tgid);
struct syms *syms__load_file(const char *fname);
void syms__free(struct syms *syms);
const struct sym *syms__map_addr(const struct syms *syms, unsigned long addr);
int syms__map_addr_dso(const struct syms *syms, unsigned long addr,
		       struct sym_info *sinfo);

struct syms_cache;

struct syms_cache *syms_cache__new(int nr);
struct syms *syms_cache__get_syms(struct syms_cache *syms_cache, int tgid);
void syms_cache__free(struct syms_cache *syms_cache);

struct partition {
	char *name;
	unsigned int dev;
};

struct partitions;

struct partitions *partitions__load(void);
void partitions__free(struct partitions *partitions);
const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev);
const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name);

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type);
void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
		unsigned int step, const char *val_type);

unsigned long long get_ktime_ns(void);

bool is_kernel_module(const char *name);

/*
 * When attempting to use kprobe/kretprobe, please check out new fentry/fexit
 * probes, as they provide better performance and usability. But in some
 * situations we have to fallback to kprobe/kretprobe probes. This helper
 * is used to detect fentry/fexit support for the specified kernel function.
 *
 *	1. A gap between kernel versions, kernel BTF is exposed
 * 	   starting from 5.4 kernel. but fentry/fexit is actually
 * 	   supported starting from 5.5.
 *	2. Whether kernel supports module BTF or not
 *
 * *name* is the name of a kernel function to be attached to, which can be
 * from vmlinux or a kernel module.
 * *mod* is a hint that indicates the *name* may reside in module BTF,
 * if NULL, it means *name* belongs to vmlinux.
 */
bool fentry_can_attach(const char *name, const char *mod);

/*
 * The name of a kernel function to be attached to may be changed between
 * kernel releases. This helper is used to confirm whether the target kernel
 * uses a certain function name before attaching.
 *
 * It is achieved by scaning
 * 	/sys/kernel/debug/tracing/available_filter_functions
 * If this file does not exist, it fallbacks to parse /proc/kallsyms,
 * which is slower.
 */
bool kprobe_exists(const char *name);
bool tracepoint_exists(const char *category, const char *event);

bool vmlinux_btf_exists(void);
bool module_btf_exists(const char *mod);

bool probe_tp_btf(const char *name);
bool probe_ringbuf();
bool probe_bpf_ns_current_pid_tgid(void);

typedef int (*convert_fn_t)(const char *src, void *dest);
int split_convert(char *s, const char* delim, void *elems, size_t elems_size,
		  size_t elem_size, convert_fn_t convert);
/*
 * Implementations of convert_fn_t.
 * This can be replaced with a user-defined callback function.
 */
/* converts a string to an integer */
int str_to_int(const char *src, void *dest);
/* converts a string to a long integer */
int str_to_long(const char *src, void *dest);

/*
 * get loadavg string with or without timestamp
 *
 * If the @buf_len is not long enough, we still provide a truncated string,
 * but return -ERANGE.
 */
int str_loadavg(char *buf, size_t buf_len);

/*
 * get format date and time
 *
 * this function encapsulates the strftime() function, and the return value
 * is the same as strftime().
 */
int str_timestamp(const char *format, char *buf, size_t buf_len);

/* ── time_sync: BPF ktime (CLOCK_MONOTONIC) → Unix epoch conversion ── */

/**
 * struct time_sync - Reference point for BPF ktime → realtime conversion.
 *
 * Populated once by sync_time() at program start. Used by
 * convert_to_realtime_ns() to translate bpf_ktime_get_ns() values into
 * CLOCK_REALTIME (Unix epoch) nanoseconds.
 */
struct time_sync {
	uint64_t monotonic_ns;  /* CLOCK_MONOTONIC snapshot (ns) */
	uint64_t realtime_ns;   /* CLOCK_REALTIME  snapshot (ns) */
};

/**
 * sync_time - Capture a MONOTONIC/REALTIME reference point.
 *
 * Must be called once near program start (before any BPF events arrive)
 * so that both clocks are sampled as close together as possible.
 */
void sync_time(struct time_sync *sync);

/**
 * convert_to_realtime_ns - Convert a BPF ktime value to Unix epoch ns.
 * @kernel_ns: value returned by bpf_ktime_get_ns() (CLOCK_MONOTONIC)
 * @sync:      reference point initialised by sync_time()
 *
 * Returns the corresponding CLOCK_REALTIME nanosecond timestamp.
 *
 * NOTE: Use 1000000000ULL (not 1e9) to avoid double-precision loss.
 */
uint64_t convert_to_realtime_ns(uint64_t kernel_ns,
				const struct time_sync *sync);

/* ── OTLP span output helpers ── */

/**
 * enum trace_output_format - Output formats for trace (span) data.
 *
 * Separate from enum output_format (which is for metric output).
 * Trace and metric data models differ fundamentally (span vs aggregation),
 * so they use independent format enums.
 */
enum trace_output_format {
	TRACE_FORMAT_OTEL_SPAN_JSON = 0,  /* OTLP Span JSONL */
	/* TRACE_FORMAT_PERFETTO,         -- Phase 3 확장 예정 */
	TRACE_FORMAT_MAX,
};

/**
 * enum span_kind - OTLP SpanKind values.
 */
enum span_kind {
	SPAN_KIND_UNSPECIFIED = 0,
	SPAN_KIND_INTERNAL    = 1,
	SPAN_KIND_SERVER      = 2,
	SPAN_KIND_CLIENT      = 3,
};

/**
 * enum span_status_code - OTLP span status codes.
 */
enum span_status_code {
	SPAN_STATUS_UNSET = 0,
	SPAN_STATUS_OK    = 1,
	SPAN_STATUS_ERROR = 2,
};

#define SPAN_NAME_LEN      128

/**
 * struct span - Userspace OTLP-compatible span record.
 *
 * Populated from a BPF ring-buffer event and passed to print_span().
 * IDs are stored as numeric types for memory efficiency (24 bytes vs 67).
 * Hex string conversion is performed at output time in print_span().
 *
 * Layout is aligned with struct functrace_event for minimal conversion.
 */
struct span {
	uint64_t              trace_id_hi;         /* 128bit trace ID upper 64bit */
	uint64_t              trace_id_lo;         /* 128bit trace ID lower 64bit */
	uint64_t              span_id;             /* 64bit span ID */
	uint64_t              parent_span_id;      /* 0 = root span */
	char                  name[SPAN_NAME_LEN];
	enum span_kind        kind;
	uint64_t              start_time_unix_nano;
	uint64_t              end_time_unix_nano;
	enum span_status_code status_code;
	uint32_t              pid;
	uint32_t              tid;
};

/**
 * print_span - Emit a span record to @fp in the requested @fmt.
 * @s:   span to print (must not be NULL)
 * @fmt: TRACE_FORMAT_OTEL_SPAN_JSON (향후 TRACE_FORMAT_PERFETTO 확장)
 * @fp:  output stream; NULL defaults to stdout
 *
 * trace_id/span_id/parent_span_id are converted from numeric to
 * hex string at output time.
 *
 * Calls fflush(fp) after each write.
 * Returns 0 on success, -EINVAL on bad arguments.
 */
int print_span(const struct span *s, enum trace_output_format fmt, FILE *fp);

#endif /* __TRACE_HELPERS_H */
