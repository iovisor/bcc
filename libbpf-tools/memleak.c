// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
//
// Based on memleak(8) from BCC by Sasha Goldshtein and others.
// 1-Mar-2023   JP Kobryn   Created this.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

static struct env {
	int interval;
	int nr_intervals;
	pid_t pid;
	bool trace_all;
	bool show_allocs;
	bool combined_only;
	long min_age_ns;
	uint64_t sample_rate;
	int top_stacks;
	size_t min_size;
	size_t max_size;
	char object[32];

	bool wa_missing_free;
	bool percpu;
	int perf_max_stack_depth;
	int stack_map_max_entries;
	long page_size;
	bool kernel_trace;
	bool verbose;
	char command[32];
	char symbols_prefix[16];
} env = {
	.interval = 5, // posarg 1
	.nr_intervals = -1, // posarg 2
	.pid = -1, // -p --pid
	.trace_all = false, // -t --trace
	.show_allocs = false, // -a --show-allocs
	.combined_only = false, // --combined-only
	.min_age_ns = 500, // -o --older (arg * 1e6)
	.wa_missing_free = false, // --wa-missing-free
	.sample_rate = 1, // -s --sample-rate
	.top_stacks = 10, // -T --top
	.min_size = 0, // -z --min-size
	.max_size = -1, // -Z --max-size
	.object = {0}, // -O --obj
	.percpu = false, // --percpu
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 10240,
	.page_size = 1,
	.kernel_trace = true,
	.verbose = false,
	.command = {0}, // -c --command
	.symbols_prefix = {0},
};

struct allocation_node {
	uint64_t address;
	size_t size;
	struct allocation_node* next;
};

struct allocation {
	int64_t stack_id;
	size_t size;
	size_t count;
	struct allocation_node* allocations;
};

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
	do { \
		char sym[32]; \
		sprintf(sym, "%s%s", env.symbols_prefix, #sym_name); \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
				.func_name = sym, \
				.retprobe = is_retprobe); \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
				skel->progs.prog_name, \
				env.pid, \
				env.object, \
				0, \
				&uprobe_opts); \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name) \
	do { \
		if (!skel->links.prog_name) { \
			perror("no program attached for " #prog_name); \
			return -errno; \
		} \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do { \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
		__CHECK_PROGRAM(skel, prog_name); \
	} while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

/*
 * -EFAULT in get_stackid normally means the stack-trace is not available,
 * such as getting kernel stack trace in user mode
 */
#define STACK_ID_EFAULT(stack_id)	(stack_id == -EFAULT)

#define STACK_ID_ERR(stack_id)		((stack_id < 0) && !STACK_ID_EFAULT(stack_id))

/* hash collision (-EEXIST) suggests that stack map size may be too small */
#define STACK_ID_COLLISION(stack_id)		(stack_id == -EEXIST)

static void sig_handler(int signo);

static long argp_parse_long(int key, const char *arg, struct argp_state *state);
static error_t argp_parse_arg(int key, char *arg, struct argp_state *state);

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

static int event_init(int *fd);
static int event_wait(int fd, uint64_t expected_event);
static int event_notify(int fd, uint64_t event);

static pid_t fork_sync_exec(const char *command, int fd);

#ifdef USE_BLAZESYM
static void print_stack_frame_by_blazesym(size_t frame, uint64_t addr, const blazesym_csym *sym);
static void print_stack_frames_by_blazesym();
#else
static void print_stack_frames_by_ksyms();
static void print_stack_frames_by_syms_cache();
#endif
static int print_stack_frames(struct allocation *allocs, size_t nr_allocs, int stack_traces_fd);

static int alloc_size_compare(const void *a, const void *b);

static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd);
static int print_outstanding_combined_allocs(int combined_allocs_fd, int stack_traces_fd);

static bool has_kernel_node_tracepoints();
static void disable_kernel_node_tracepoints(struct memleak_bpf *skel);
static void disable_kernel_percpu_tracepoints(struct memleak_bpf *skel);
static void disable_kernel_tracepoints(struct memleak_bpf *skel);

static int attach_uprobes(struct memleak_bpf *skel);

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace outstanding memory allocations\n"
"\n"
"USAGE: memleak [-h] [-c COMMAND] [-p PID] [-t] [-n] [-a] [-o AGE_MS] [-C] [-F] [-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJECT] [-P] [INTERVAL] [INTERVALS]\n"
"\n"
"EXAMPLES:\n"
"./memleak -p $(pidof allocs)\n"
"        Trace allocations and display a summary of 'leaked' (outstanding)\n"
"        allocations every 5 seconds\n"
"./memleak -p $(pidof allocs) -t\n"
"        Trace allocations and display each individual allocator function call\n"
"./memleak -ap $(pidof allocs) 10\n"
"        Trace allocations and display allocated addresses, sizes, and stacks\n"
"        every 10 seconds for outstanding allocations\n"
"./memleak -c './allocs'\n"
"        Run the specified command and trace its allocations\n"
"./memleak\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations every 5 seconds\n"
"./memleak -o 60000\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations that are at least one minute (60 seconds) old\n"
"./memleak -s 5\n"
"        Trace roughly every 5th allocation, to reduce overhead\n"
"./memleak -p $(pidof allocs) -S je_\n"
"        Trace task who sue jemalloc\n"
"";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "process ID to trace. if not specified, trace kernel allocs", 0 },
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call", 0 },
	{"show-allocs", 'a', 0, 0, "show allocation addresses and sizes as well as call stacks", 0 },
	{"older", 'o', "AGE_MS", 0, "prune allocations younger than this age in milliseconds", 0 },
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command", 0 },
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only", 0 },
	{"wa-missing-free", 'F', 0, 0, "workaround to alleviate misjudgments when free is missing", 0 },
	{"sample-rate", 's', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease the overhead", 0 },
	{"top", 'T', "TOP_STACKS", 0, "display only this many top allocating stacks (by size)", 0 },
	{"min-size", 'z', "MIN_SIZE", 0, "capture only allocations larger than or equal to this size", 0 },
	{"max-size", 'Z', "MAX_SIZE", 0, "capture only allocations smaller than or equal to this size", 0 },
	{"obj", 'O', "OBJECT", 0, "attach to allocator functions in the specified object", 0 },
	{"percpu", 'P', NULL, 0, "trace percpu allocations", 0 },
	{"symbols-prefix", 'S', "SYMBOLS_PREFIX", 0, "memory allocator symbols prefix", 0 },
	{"stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	 "the number of unique stack traces that can be stored and displayed (default 10240)", 0 },
	{"perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	 "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{"verbose", 'v', NULL, 0, "verbose debug output", 0 },
	{},
};

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t child_exited;

static struct sigaction sig_action = {
	.sa_handler = sig_handler
};

static int child_exec_event_fd = -1;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
static sym_src_cfg src_cfg;
#else
struct syms_cache *syms_cache;
struct ksyms *ksyms;
#endif
static void (*print_stack_frames_func)();

static uint64_t *stack;

static struct allocation *allocs;

static const char default_object[] = "libc.so.6";

int main(int argc, char *argv[])
{
	int ret = 0;
	struct memleak_bpf *skel = NULL;

	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	// parse command line args to env settings
	if (argp_parse(&argp, argc, argv, 0, NULL, NULL)) {
		fprintf(stderr, "failed to parse args\n");

		goto cleanup;
	}

	// install signal handler
	if (sigaction(SIGINT, &sig_action, NULL) || sigaction(SIGCHLD, &sig_action, NULL)) {
		perror("failed to set up signal handling");
		ret = -errno;

		goto cleanup;
	}

	// post-processing and validation of env settings
	if (env.min_size > env.max_size) {
		fprintf(stderr, "min size (-z) can't be greater than max_size (-Z)\n");
		return 1;
	}

	if (!strlen(env.object)) {
		printf("using default object: %s\n", default_object);
		strncpy(env.object, default_object, sizeof(env.object) - 1);
	}

	env.page_size = sysconf(_SC_PAGE_SIZE);
	printf("using page size: %ld\n", env.page_size);

	env.kernel_trace = env.pid < 0 && !strlen(env.command);

	// if specific userspace program was specified,
	// create the child process and use an eventfd to synchronize the call to exec()
	if (strlen(env.command)) {
		if (env.pid >= 0) {
			fprintf(stderr, "cannot specify both command and pid\n");
			ret = 1;

			goto cleanup;
		}

		if (event_init(&child_exec_event_fd)) {
			fprintf(stderr, "failed to init child event\n");

			goto cleanup;
		}

		const pid_t child_pid = fork_sync_exec(env.command, child_exec_event_fd);
		if (child_pid < 0) {
			perror("failed to spawn child process");
			ret = -errno;

			goto cleanup;
		}

		env.pid = child_pid;
	}

	// allocate space for storing a stack trace
	stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
	if (!stack) {
		fprintf(stderr, "failed to allocate stack array\n");
		ret = -ENOMEM;

		goto cleanup;
	}

#ifdef USE_BLAZESYM
	if (env.pid < 0) {
		src_cfg.src_type = SRC_T_KERNEL;
		src_cfg.params.kernel.kallsyms = NULL;
		src_cfg.params.kernel.kernel_image = NULL;
	} else {
		src_cfg.src_type = SRC_T_PROCESS;
		src_cfg.params.process.pid = env.pid;
	}
#endif

	// allocate space for storing "allocation" structs
	if (env.combined_only)
		allocs = calloc(COMBINED_ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	else
		allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));

	if (!allocs) {
		fprintf(stderr, "failed to allocate array\n");
		ret = -ENOMEM;

		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		ret = 1;

		goto cleanup;
	}

	skel->rodata->min_size = env.min_size;
	skel->rodata->max_size = env.max_size;
	skel->rodata->page_size = env.page_size;
	skel->rodata->sample_rate = env.sample_rate;
	skel->rodata->trace_all = env.trace_all;
	skel->rodata->stack_flags = env.kernel_trace ? 0 : BPF_F_USER_STACK;
	skel->rodata->wa_missing_free = env.wa_missing_free;

	bpf_map__set_value_size(skel->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_map_max_entries);

	if (env.combined_only) {
		bpf_map__set_max_entries(skel->maps.combined_allocs, COMBINED_ALLOCS_MAX_ENTRIES);
		skel->rodata->combined_only = true;
	}

	// disable kernel tracepoints based on settings or availability
	if (env.kernel_trace) {
		if (!has_kernel_node_tracepoints())
			disable_kernel_node_tracepoints(skel);

		if (!env.percpu)
			disable_kernel_percpu_tracepoints(skel);
	} else {
		disable_kernel_tracepoints(skel);
	}

	ret = memleak_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load bpf object\n");

		goto cleanup;
	}

	const int allocs_fd = bpf_map__fd(skel->maps.allocs);
	const int combined_allocs_fd = bpf_map__fd(skel->maps.combined_allocs);
	const int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);

	// if userspace oriented, attach uprobes
	if (!env.kernel_trace) {
		printf("Attaching to pid %d, Ctrl+C to quit.\n", env.pid);
		ret = attach_uprobes(skel);
		if (ret) {
			fprintf(stderr, "failed to attach uprobes\n");

			goto cleanup;
		}
	} else {
		printf("Attaching to kernel allocators, Ctrl+C to quit.\n");
	}

	ret = memleak_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "failed to attach bpf program(s)\n");

		goto cleanup;
	}

	// if running a specific userspace program,
	// notify the child process that it can exec its program
	if (strlen(env.command)) {
		ret = event_notify(child_exec_event_fd, 1);
		if (ret) {
			fprintf(stderr, "failed to notify child to perform exec\n");

			goto cleanup;
		}
	}

#ifdef USE_BLAZESYM
	symbolizer = blazesym_new();
	if (!symbolizer) {
		fprintf(stderr, "Failed to load blazesym\n");
		ret = -ENOMEM;

		goto cleanup;
	}
	print_stack_frames_func = print_stack_frames_by_blazesym;
#else
	if (env.kernel_trace) {
		ksyms = ksyms__load();
		if (!ksyms) {
			fprintf(stderr, "Failed to load ksyms\n");
			ret = -ENOMEM;

			goto cleanup;
		}
		print_stack_frames_func = print_stack_frames_by_ksyms;
	} else {
		syms_cache = syms_cache__new(0);
		if (!syms_cache) {
			fprintf(stderr, "Failed to create syms_cache\n");
			ret = -ENOMEM;

			goto cleanup;
		}
		print_stack_frames_func = print_stack_frames_by_syms_cache;
	}
#endif

	// main loop
	while (!exiting && env.nr_intervals) {
		env.nr_intervals--;

		sleep(env.interval);

		if (env.combined_only)
			print_outstanding_combined_allocs(combined_allocs_fd, stack_traces_fd);
		else
			print_outstanding_allocs(allocs_fd, stack_traces_fd);
	}

	// after loop ends, check for child process and cleanup accordingly
	if (env.pid > 0 && strlen(env.command)) {
		if (!child_exited) {
			if (kill(env.pid, SIGTERM)) {
				perror("failed to signal child process");
				ret = -errno;

				goto cleanup;
			}
			printf("signaled child process\n");
		}

		if (waitpid(env.pid, NULL, 0) < 0) {
			perror("failed to reap child process");
			ret = -errno;

			goto cleanup;
		}
		printf("reaped child process\n");
	}

cleanup:
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#else
	if (syms_cache)
		syms_cache__free(syms_cache);
	if (ksyms)
		ksyms__free(ksyms);
#endif
	memleak_bpf__destroy(skel);

	free(allocs);
	free(stack);

	printf("done\n");

	return ret;
}

long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args = 0;
	long age_ms;

	switch (key) {
	case 'p':
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'a':
		env.show_allocs = true;
		break;
	case 'o':
		age_ms = argp_parse_long(key, arg, state);
		if (age_ms > (LONG_MAX / 1e6) || age_ms < (LONG_MIN / 1e6)) {
			fprintf(stderr, "invalid AGE_MS: %s\n", arg);
			argp_usage(state);
		}
		env.min_age_ns = age_ms * 1e6;
		break;
	case 'c':
		strncpy(env.command, arg, sizeof(env.command) - 1);
		break;
	case 'C':
		env.combined_only = true;
		break;
	case 'F':
		env.wa_missing_free = true;
		break;
	case 's':
		env.sample_rate = argp_parse_long(key, arg, state);
		break;
	case 'S':
		strncpy(env.symbols_prefix, arg, sizeof(env.symbols_prefix) - 1);
		break;
	case 'T':
		env.top_stacks = argp_parse_long(key, arg, state);
		break;
	case 'z':
		env.min_size = argp_parse_long(key, arg, state);
		break;
	case 'Z':
		env.max_size = argp_parse_long(key, arg, state);
		break;
	case 'O':
		strncpy(env.object, arg, sizeof(env.object) - 1);
		break;
	case 'P':
		env.percpu = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_map_max_entries = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		pos_args++;

		if (pos_args == 1) {
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2) {
			env.nr_intervals = argp_parse_long(key, arg, state);
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void sig_handler(int signo)
{
	if (signo == SIGCHLD)
		child_exited = 1;

	exiting = 1;
}

int event_init(int *fd)
{
	if (!fd) {
		fprintf(stderr, "pointer to fd is null\n");

		return 1;
	}

	const int tmp_fd = eventfd(0, EFD_CLOEXEC);
	if (tmp_fd < 0) {
		perror("failed to create event fd");

		return -errno;
	}

	*fd = tmp_fd;

	return 0;
}

int event_wait(int fd, uint64_t expected_event)
{
	uint64_t event = 0;
	const ssize_t bytes = read(fd, &event, sizeof(event));
	if (bytes < 0) {
		perror("failed to read from fd");

		return -errno;
	} else if (bytes != sizeof(event)) {
		fprintf(stderr, "read unexpected size\n");

		return 1;
	}

	if (event != expected_event) {
		fprintf(stderr, "read event %lu, expected %lu\n", event, expected_event);

		return 1;
	}

	return 0;
}

int event_notify(int fd, uint64_t event)
{
	const ssize_t bytes = write(fd, &event, sizeof(event));
	if (bytes < 0) {
		perror("failed to write to fd");

		return -errno;
	} else if (bytes != sizeof(event)) {
		fprintf(stderr, "attempted to write %zu bytes, wrote %zd bytes\n", sizeof(event), bytes);

		return 1;
	}

	return 0;
}

pid_t fork_sync_exec(const char *command, int fd)
{
	const pid_t pid = fork();

	switch (pid) {
	case -1:
		perror("failed to create child process");
		break;
	case 0: {
		const uint64_t event = 1;
		if (event_wait(fd, event)) {
			fprintf(stderr, "failed to wait on event");
			exit(EXIT_FAILURE);
		}

		printf("received go event. executing child command\n");

		const int err = execl(command, command, NULL);
		if (err) {
			perror("failed to execute child command");
			return -1;
		}

		break;
	}
	default:
		printf("child created with pid: %d\n", pid);

		break;
	}

	return pid;
}

#ifdef USE_BLAZESYM
void print_stack_frame_by_blazesym(size_t frame, uint64_t addr, const blazesym_csym *sym)
{
	if (!sym)
		printf("\t%zu [<%016lx>] <%s>\n", frame, addr, "null sym");
	else if (sym->path && strlen(sym->path))
		printf("\t%zu [<%016lx>] %s+0x%lx %s:%ld\n", frame, addr, sym->symbol, addr - sym->start_address, sym->path, sym->line_no);
	else
		printf("\t%zu [<%016lx>] %s+0x%lx\n", frame, addr, sym->symbol, addr - sym->start_address);
}

void print_stack_frames_by_blazesym()
{
	const blazesym_result *result = blazesym_symbolize(symbolizer, &src_cfg, 1, stack, env.perf_max_stack_depth);

	for (size_t j = 0; j < result->size; ++j) {
		const uint64_t addr = stack[j];

		if (addr == 0)
			break;

		// no symbol found
		if (!result || j >= result->size || result->entries[j].size == 0) {
			print_stack_frame_by_blazesym(j, addr, NULL);

			continue;
		}

		// single symbol found
		if (result->entries[j].size == 1) {
			const blazesym_csym *sym = &result->entries[j].syms[0];
			print_stack_frame_by_blazesym(j, addr, sym);

			continue;
		}

		// multi symbol found
		printf("\t%zu [<%016lx>] (%lu entries)\n", j, addr, result->entries[j].size);

		for (size_t k = 0; k < result->entries[j].size; ++k) {
			const blazesym_csym *sym = &result->entries[j].syms[k];
			if (sym->path && strlen(sym->path))
				printf("\t\t%s@0x%lx %s:%ld\n", sym->symbol, sym->start_address, sym->path, sym->line_no);
			else
				printf("\t\t%s@0x%lx\n", sym->symbol, sym->start_address);
		}
	}

	blazesym_result_free(result);
}
#else
void print_stack_frames_by_ksyms()
{
	for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
		const uint64_t addr = stack[i];

		if (addr == 0)
			break;

		const struct ksym *ksym = ksyms__map_addr(ksyms, addr);
		if (ksym)
			printf("\t%zu [<%016lx>] %s+0x%lx\n", i, addr, ksym->name, addr - ksym->addr);
		else
			printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
	}
}

void print_stack_frames_by_syms_cache()
{
	const struct syms *syms = syms_cache__get_syms(syms_cache, env.pid);
	if (!syms) {
		fprintf(stderr, "Failed to get syms\n");
		return;
	}

	for (size_t i = 0; i < env.perf_max_stack_depth; ++i) {
		const uint64_t addr = stack[i];

		if (addr == 0)
			break;

		struct sym_info sinfo;
		int ret = syms__map_addr_dso(syms, addr, &sinfo);
		if (ret == 0) {
			printf("\t%zu [<%016lx>]", i, addr);
			if (sinfo.sym_name)
				printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
			printf(" [%s]\n", sinfo.dso_name);
		} else {
			printf("\t%zu [<%016lx>] <%s>\n", i, addr, "null sym");
		}
	}
}
#endif

int print_stack_frames(struct allocation *allocs, size_t nr_allocs, int stack_traces_fd)
{
	for (size_t i = 0; i < nr_allocs; ++i) {
		const struct allocation *alloc = &allocs[i];

		printf("%zu bytes in %zu allocations from stack\n", alloc->size, alloc->count);

		if (env.show_allocs) {
			struct allocation_node* it = alloc->allocations;
			while (it != NULL) {
				printf("\taddr = %#lx size = %zu\n", it->address, it->size);
				it = it->next;
			}
		}

		if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack)) {
			if (errno == ENOENT)
				continue;

			perror("failed to lookup stack trace");

			return -errno;
		}

		(*print_stack_frames_func)();
	}

	return 0;
}

int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order

	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

int print_outstanding_allocs(int allocs_fd, int stack_traces_fd)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	size_t nr_allocs = 0;
	size_t nr_missing_stacks = 0;
	size_t nr_collision_stacks = 0;

	// for each struct alloc_info "alloc_info" in the bpf map "allocs"
	for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key) {
		struct alloc_info alloc_info = {};
		memset(&alloc_info, 0, sizeof(alloc_info));

		if (bpf_map_get_next_key(allocs_fd, &prev_key, &curr_key)) {
			if (errno == ENOENT) {
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}

		if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info)) {
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			return -errno;
		}

		// filter by age
		if (get_ktime_ns() - env.min_age_ns < alloc_info.timestamp_ns) {
			continue;
		}

		// filter invalid stacks
		if (alloc_info.stack_id < 0) {
			/* handle stack id errors */
			nr_missing_stacks += STACK_ID_ERR(alloc_info.stack_id);
			nr_collision_stacks += STACK_ID_COLLISION(alloc_info.stack_id);

			continue;
		}

		// when the stack_id exists in the allocs array,
		//   increment size with alloc_info.size
		bool stack_exists = false;

		for (size_t i = 0; !stack_exists && i < nr_allocs; ++i) {
			struct allocation *alloc = &allocs[i];

			if (alloc->stack_id == alloc_info.stack_id) {
				alloc->size += alloc_info.size;
				alloc->count++;

				if (env.show_allocs) {
					struct allocation_node* node = malloc(sizeof(struct allocation_node));
					if (!node) {
						perror("malloc failed");
						return -errno;
					}
					node->address = curr_key;
					node->size = alloc_info.size;
					node->next = alloc->allocations;
					alloc->allocations = node;
				}

				stack_exists = true;
				break;
			}
		}

		if (stack_exists)
			continue;

		// when the stack_id does not exist in the allocs array,
		//   create a new entry in the array
		struct allocation alloc = {
			.stack_id = alloc_info.stack_id,
			.size = alloc_info.size,
			.count = 1,
			.allocations = NULL
		};

		if (env.show_allocs) {
			struct allocation_node* node = malloc(sizeof(struct allocation_node));
			if (!node) {
				perror("malloc failed");
				return -errno;
			}
			node->address = curr_key;
			node->size = alloc_info.size;
			node->next = NULL;
			alloc.allocations = node;
		}

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	// sort the allocs array in descending order
	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
	size_t nr_allocs_to_show = nr_allocs < env.top_stacks ? nr_allocs : env.top_stacks;

	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs_to_show);

	print_stack_frames(allocs, nr_allocs_to_show, stack_traces_fd);

	// Reset allocs list so that we dont accidentaly reuse data the next time we call this function
	for (size_t i = 0; i < nr_allocs; i++) {
		allocs[i].stack_id = 0;
		if (env.show_allocs) {
			struct allocation_node *it = allocs[i].allocations;
			while (it != NULL) {
				struct allocation_node *this = it;
				it = it->next;
				free(this);
			}
			allocs[i].allocations = NULL;
		}
	}

	if (nr_missing_stacks > 0) {
		fprintf(stderr, "WARNING: %zu stack traces could not be displayed"
			" due to memory shortage, including %zu caused by hash collisions."
			" Consider increasing --stack-storage-size.\n",
			nr_missing_stacks, nr_collision_stacks);
	}

	return 0;
}

int print_outstanding_combined_allocs(int combined_allocs_fd, int stack_traces_fd)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	size_t nr_allocs = 0;
	size_t nr_missing_stacks = 0;
	size_t nr_collision_stacks = 0;

	// for each stack_id "curr_key" and union combined_alloc_info "alloc"
	// in bpf_map "combined_allocs"
	for (uint64_t prev_key = 0, curr_key = 0;; prev_key = curr_key) {
		union combined_alloc_info combined_alloc_info;
		memset(&combined_alloc_info, 0, sizeof(combined_alloc_info));

		if (bpf_map_get_next_key(combined_allocs_fd, &prev_key, &curr_key)) {
			if (errno == ENOENT) {
				break; // no more keys, done
			}

			perror("map get next key error");

			return -errno;
		}

		if (bpf_map_lookup_elem(combined_allocs_fd, &curr_key, &combined_alloc_info)) {
			if (errno == ENOENT)
				continue;

			perror("map lookup error");

			return -errno;
		}

		const struct allocation alloc = {
			.stack_id = curr_key,
			.size = combined_alloc_info.total_size,
			.count = combined_alloc_info.number_of_allocs,
			.allocations = NULL
		};

		// filter invalid stacks
		if (alloc.stack_id < 0) {
			/* handle stack id errors */
			if (STACK_ID_ERR(alloc.stack_id))
				nr_missing_stacks += alloc.count;
			if (STACK_ID_COLLISION(alloc.stack_id))
				nr_collision_stacks += alloc.count;
			continue;
		}

		memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
		nr_allocs++;
	}

	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
	nr_allocs = nr_allocs < env.top_stacks ? nr_allocs : env.top_stacks;

	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs);

	print_stack_frames(allocs, nr_allocs, stack_traces_fd);

	if (nr_missing_stacks > 0) {
		fprintf(stderr, "WARNING: %zu stack traces could not be displayed"
			" due to memory shortage, including %zu caused by hash collisions."
			" Consider increasing --stack-storage-size.\n",
			nr_missing_stacks, nr_collision_stacks);
	}

	return 0;
}

bool has_kernel_node_tracepoints()
{
	return tracepoint_exists("kmem", "kmalloc_node") &&
		tracepoint_exists("kmem", "kmem_cache_alloc_node");
}

void disable_kernel_node_tracepoints(struct memleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
}

void disable_kernel_percpu_tracepoints(struct memleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

void disable_kernel_tracepoints(struct memleak_bpf *skel)
{
	bpf_program__set_autoload(skel->progs.memleak__kmalloc, false);
	bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kfree, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_free, false);
	bpf_program__set_autoload(skel->progs.memleak__mm_page_alloc, false);
	bpf_program__set_autoload(skel->progs.memleak__mm_page_free, false);
	bpf_program__set_autoload(skel->progs.memleak__percpu_alloc_percpu, false);
	bpf_program__set_autoload(skel->progs.memleak__percpu_free_percpu, false);
}

int attach_uprobes(struct memleak_bpf *skel)
{
	ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);

	ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

	ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

	/* third party allocator like jemallloc not support mmap, so remove the check. */
	if (strlen(env.symbols_prefix)) {
		ATTACH_UPROBE(skel, mmap, mmap_enter);
		ATTACH_URETPROBE(skel, mmap, mmap_exit);

		ATTACH_UPROBE(skel, mremap, mmap_enter);
		ATTACH_URETPROBE(skel, mremap, mmap_exit);
	} else {
		ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
		ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

		ATTACH_UPROBE_CHECKED(skel, mremap, mremap_enter);
		ATTACH_URETPROBE_CHECKED(skel, mremap, mremap_exit);
	}

	ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, free, free_enter);
	if (strlen(env.symbols_prefix))
		ATTACH_UPROBE(skel, munmap, munmap_enter);
	else
		ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

	// the following probes are intentinally allowed to fail attachment

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, valloc, valloc_enter);
	ATTACH_URETPROBE(skel, valloc, valloc_exit);

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

	// added in C11
	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);


	return 0;
}
