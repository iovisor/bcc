// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * functrace  Trace userspace function calls with call tree visualisation.
 *
 * Based on funclatency from BCC by Brendan Gregg.
 * 29-Jul-2024   Eunseon Lee   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "functrace.h"
#include "functrace.skel.h"
#include "trace_helpers.h"
#include "functrace_text.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define MAX_FUNCTIONS   32
#define OUTPUT_FILE_MAX 256
#define BINARY_PATH_MAX 256

static struct env {
	bool              verbose;
	int               duration;
	pid_t             pid;
	char              functions[MAX_FUNCTIONS][FUNC_NAME_LEN];
	int               func_count;
	char              output_file[OUTPUT_FILE_MAX];
	char              binary[BINARY_PATH_MAX];
	bool              otel;       /* true = -F otel (OTLP JSONL), false = text */
	char              root_func[FUNC_NAME_LEN];
	int               root_func_idx;  /* index in functions[], -1 if unset */
	int               max_depth;
	size_t            ringbuf_sz; /* ring buffer size in bytes */
} env = {
	.duration       = 0,
	.pid            = 0,
	.func_count     = 0,
	.otel           = false,
	.root_func_idx  = -1,
	.max_depth      = MAX_CALL_DEPTH,
	.ringbuf_sz     = 1024 * 1024,  /* 1 MiB default */
};

static volatile bool  exiting  = false;
static FILE          *output_fp = NULL;
static struct time_sync tsync;
static struct functrace_bpf *g_skel = NULL;
static volatile __u64 lost_events = 0;

const char *argp_program_version     = "functrace 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "-b BINARY -f FUNC [-f FUNC2 ...]";
static const char program_doc[] =
"Trace userspace function calls with call tree visualisation.\n"
"\n"
"USAGE: functrace [OPTIONS] -b BINARY -f FUNC [-f FUNC2 ...]\n"
"\v"
"Examples:\n"
"    functrace -b ./app -f my_func                      # text diagram\n"
"    functrace -b ./app -R main -f main -f foo          # call tree\n"
"    functrace -b ./app -f f1 -f f2 -p 1234 -F otel     # OTLP JSON\n"
"    functrace -b ./app -R main -f main -d 10           # trace for 10s\n"
;

static const struct argp_option opts[] = {
	{ "function",  'f', "FUNC",    0, "Function to trace (repeatable)", 0 },
	{ "binary",    'b', "PATH",    0, "Path to binary with uprobes",    0 },
	{ "root-func", 'R', "FUNC",    0, "Root function for trace boundary (required)", 0 },
	{ 0, 0, 0, 0, "", 0 },
	{ "pid",       'p', "PID",     0, "Trace only this PID (0 = all)",  0 },
	{ "output",    'o', "FILE",    0, "Output file (default: stdout)",  0 },
	{ "format",    'F', "FMT",     0, "Output format: otel (OTLP JSONL)", 0 },
	{ "duration",  'd', "SECONDS", 0, "Trace duration (0 = until Ctrl-C)", 0 },
	{ "max-depth", 'D', "N",       0, "Max call depth (default: 64)",   0 },
	{ "ringbuf-size", 'B', "BYTES", 0, "Ring buffer size (default: 1048576)", 0 },
	{ 0, 0, 0, 0, "", 0 },
	{ "verbose",   'v', NULL,      0, "Verbose debug output",           0 },
	{ NULL,        'h', NULL, OPTION_HIDDEN, "Show help",               0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long num;

	switch (key) {
	case 'f':
		if (env.func_count >= MAX_FUNCTIONS) {
			warn("Too many functions (max %d)\n", MAX_FUNCTIONS);
			argp_usage(state);
		}
		strncpy(env.functions[env.func_count++], arg,
			FUNC_NAME_LEN - 1);
		break;
	case 'b':
		strncpy(env.binary, arg, BINARY_PATH_MAX - 1);
		break;
	case 'p':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = num;
		break;
	case 'o':
		strncpy(env.output_file, arg, OUTPUT_FILE_MAX - 1);
		break;
	case 'F':
		if (strcmp(arg, "otel") == 0)
			env.otel = true;
		else {
			warn("Unknown format '%s' (use 'otel')\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num < 0) {
			warn("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		env.duration = num;
		break;
	case 'R':
		strncpy(env.root_func, arg, FUNC_NAME_LEN - 1);
		break;
	case 'D':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0 || num > MAX_CALL_DEPTH) {
			warn("Invalid max-depth (1-%d): %s\n",
				MAX_CALL_DEPTH, arg);
			argp_usage(state);
		}
		env.max_depth = num;
		break;
	case 'B':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			warn("Invalid ringbuf-size: %s\n", arg);
			argp_usage(state);
		}
		env.ringbuf_sz = num;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options  = opts,
	.parser   = parse_arg,
	.args_doc = args_doc,
	.doc      = program_doc,
};

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_lost_events(void *ctx, int cpu, __u64 cnt)
{
	lost_events += cnt;
	warn("Lost %llu events on CPU #%d\n", cnt, cpu);
}

/**
 * generate_trace_id_128 - Generate a 128-bit random trace ID.
 *
 * Uses getrandom(2) for cryptographic quality randomness.
 * Falls back to prandom if getrandom fails.
 */
static void generate_trace_id_128(uint64_t *hi, uint64_t *lo)
{
	uint64_t buf[2];

	if (getrandom(buf, sizeof(buf), 0) == sizeof(buf)) {
		*hi = buf[0];
		*lo = buf[1];
	} else {
		/* fallback */
		*hi = ((uint64_t)rand() << 32) | rand();
		*lo = ((uint64_t)rand() << 32) | rand();
	}
	/* Ensure traceId is non-zero (OTLP requirement) */
	if (*hi == 0 && *lo == 0)
		*lo = 1;
}

/**
 * inject_trace_id - Pre-inject a 128-bit traceId into BPF maps for a tid.
 *
 * Called on root-func exit event to prepare the next trace's ID.
 * Also called at startup to seed initial traceId for each potential thread.
 */
static void inject_trace_id(uint32_t tid)
{
	uint64_t hi, lo;

	generate_trace_id_128(&hi, &lo);

	int hi_fd = bpf_map__fd(g_skel->maps.trace_id_hi_map);
	int lo_fd = bpf_map__fd(g_skel->maps.trace_id_lo_map);

	bpf_map_update_elem(hi_fd, &tid, &hi, BPF_ANY);
	bpf_map_update_elem(lo_fd, &tid, &lo, BPF_ANY);

	if (env.verbose)
		fprintf(stderr, "Injected traceId %016llx%016llx for tid %u\n",
			(unsigned long long)hi, (unsigned long long)lo, tid);
}

/*
 * Ring-buffer callback — Phase 2.
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct functrace_event *e = data;

	/* Resolve function name from BPF cookie index */
	const char *func_name = "unknown";
	if (e->func_idx < (uint32_t)env.func_count)
		func_name = env.functions[e->func_idx];

	if (env.otel) {
		struct span s = {0};

		s.trace_id_hi          = e->trace_id_hi;
		s.trace_id_lo          = e->trace_id_lo;
		s.span_id              = e->span_id;
		s.parent_span_id       = e->parent_span_id;

		snprintf(s.name, SPAN_NAME_LEN, "%s", func_name);
		s.kind                = SPAN_KIND_INTERNAL;
		s.start_time_unix_nano = convert_to_realtime_ns(e->start_ns,
								&tsync);
		s.end_time_unix_nano   = convert_to_realtime_ns(e->end_ns,
								&tsync);
		s.status_code         = SPAN_STATUS_OK;
		s.pid                 = e->pid;
		s.tid                 = e->tid;

		print_span(&s, TRACE_FORMAT_OTEL_SPAN_JSON, output_fp);
	} else {
		text_handle_span(e, func_name, output_fp);
	}

	/* On root-func exit, inject next traceId for this tid */
	if (e->is_root && env.root_func[0])
		inject_trace_id(e->tid);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer     *rb   = NULL;
	struct functrace_bpf   *skel;
	int                     err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.func_count == 0) {
		warn("Error: specify at least one function with -f\n");
		return 1;
	}
	if (!env.binary[0]) {
		warn("Error: specify the binary path with -b\n");
		return 1;
	}

	/* --root-func is mandatory for trace boundary */
	if (!env.root_func[0]) {
		warn("Error: -R/--root-func is required\n");
		return 1;
	}

	/* Resolve root-func index */
	for (int i = 0; i < env.func_count; i++) {
		if (strcmp(env.root_func, env.functions[i]) == 0) {
			env.root_func_idx = i;
			break;
		}
	}
	if (env.root_func_idx < 0) {
		warn("Warning: --root-func '%s' not in -f list, "
			"adding it automatically\n", env.root_func);
		if (env.func_count >= MAX_FUNCTIONS) {
			warn("Too many functions\n");
			return 1;
		}
		snprintf(env.functions[env.func_count], FUNC_NAME_LEN,
			 "%s", env.root_func);
		env.root_func_idx = env.func_count;
		env.func_count++;
	}

	/* Snapshot clock reference before any events arrive */
	sync_time(&tsync);

	/* Initialise text output subsystem */
	text_output_init();

	/* Open output stream */
	if (env.output_file[0]) {
		output_fp = fopen(env.output_file, "a");
		if (!output_fp) {
			warn("Cannot open output file '%s': %s\n",
				env.output_file, strerror(errno));
			return 1;
		}
	} else {
		output_fp = stdout;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	skel = functrace_bpf__open();
	if (!skel) {
		warn("Failed to open BPF skeleton\n");
		return 1;
	}
	g_skel = skel;

	skel->rodata->target_pid    = env.pid;
	skel->rodata->has_root_func = env.root_func[0] ? 1 : 0;

	/* Set ring buffer size from CLI option */
	bpf_map__set_max_entries(skel->maps.rb, env.ringbuf_sz);

	err = functrace_bpf__load(skel);
	if (err) {
		warn("Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Populate root_funcs map if --root-func specified */
	if (env.root_func_idx >= 0) {
		uint64_t cookie = (uint64_t)env.root_func_idx;
		uint8_t  one    = 1;
		int rf_fd = bpf_map__fd(skel->maps.root_funcs);

		err = bpf_map_update_elem(rf_fd, &cookie, &one, BPF_ANY);
		if (err) {
			warn("Failed to set root_funcs map: %s\n",
				strerror(errno));
			goto cleanup;
		}
		if (env.verbose)
			warn("Root function: %s (cookie=%llu)\n",
				env.root_func,
				(unsigned long long)cookie);
	}

	/* Pre-inject initial traceId for tid=0 (placeholder) */
	if (env.root_func[0]) {
		/*
		 * We can't know the target TID in advance, so we
		 * pre-inject for a few common cases.  The BPF program
		 * will fall back to bpf_get_prandom_u32() if no
		 * pre-injected ID is found.
		 */
		uint32_t placeholder_tid = 0;
		inject_trace_id(placeholder_tid);
	}

	/* Attach uprobes for each function */
	for (int i = 0; i < env.func_count; i++) {
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
			.func_name = env.functions[i],
			.retprobe  = false,
			.bpf_cookie = (uint64_t)i,
		);
		struct bpf_link *entry_link =
			bpf_program__attach_uprobe_opts(
				skel->progs.trace_func_entry,
				env.pid ? env.pid : -1,
				env.binary, 0, &uprobe_opts);
		if (!entry_link) {
			warn("Failed to attach uprobe for '%s': %s\n",
				env.functions[i], strerror(errno));
			err = -errno;
			goto cleanup;
		}

		LIBBPF_OPTS(bpf_uprobe_opts, uretprobe_opts,
			.func_name = env.functions[i],
			.retprobe  = true,
			.bpf_cookie = (uint64_t)i,
		);
		struct bpf_link *exit_link =
			bpf_program__attach_uprobe_opts(
				skel->progs.trace_func_exit,
				env.pid ? env.pid : -1,
				env.binary, 0, &uretprobe_opts);
		if (!exit_link) {
			warn("Failed to attach uretprobe for '%s': %s\n",
				env.functions[i], strerror(errno));
			err = -errno;
			goto cleanup;
		}
	}

	if (env.verbose) {
		warn("Binary     : %s\n", env.binary);
		warn("Format     : %s\n", env.otel ? "otel" : "text");
		warn("Root func  : %s\n", env.root_func);
		warn("Max depth  : %d\n", env.max_depth);
		warn("Ringbuf    : %zu bytes\n", env.ringbuf_sz);
		warn("Functions  :");
		for (int i = 0; i < env.func_count; i++)
			warn(" %s", env.functions[i]);
		warn("\n");
		if (env.pid)
			warn("PID        : %u\n", env.pid);
		else
			warn("PID        : all\n");
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
			      handle_event, handle_lost_events, NULL);
	if (!rb) {
		warn("Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	warn("Tracing... Hit Ctrl-C to stop.\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			warn("Ring buffer poll error: %d\n", err);
			break;
		}

		if (env.duration > 0) {
			static time_t start_time;

			if (!start_time)
				start_time = time(NULL);
			if (time(NULL) - start_time >= env.duration) {
				/* ring_buffer__poll() returns the number of
				 * records consumed (>= 0) on success, not a
				 * pure error indicator. Reset err to 0 here
				 * so a normal duration-based exit is not
				 * mistaken for failure by `return err != 0`
				 * below just because the last poll cycle
				 * happened to process events.
				 */
				err = 0;
				break;
			}
		}
	}

cleanup:
	ring_buffer__free(rb);
	functrace_bpf__destroy(skel);
	if (output_fp && output_fp != stdout)
		fclose(output_fp);

	if (lost_events)
		warn("Lost %llu events total\n", lost_events);

	return err != 0;
}
