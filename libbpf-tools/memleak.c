#include <argp.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif
#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PATH_MAX 4096

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env {
	int interval;
	int nr_intervals;
	pid_t pid;
	bool trace_all;
	bool show_allocs;
	bool combined_only;
	int min_age_ns;
	int sample_every_n;
	int sample_rate;
	int top_stacks;
	size_t min_size;
	size_t max_size;
	char *object;

	bool wa_missing_free;
	bool percpu;
	int perf_max_stack_depth;
	int stack_max_entries;
	long page_size;
	bool kernel_trace;
	bool verbose;
	char *command;
} env = {
	.interval = 5, // posarg 1
	.nr_intervals = 0, // posarg 2
	.pid = -1, // -p --pid
	.trace_all = false, // -t --trace
	.show_allocs = false, // -a --show-allocs
	.combined_only = false, // --combined-only
	.min_age_ns = 500, // -o --older val * 1e6
	.wa_missing_free = false, // --wa-missing-free
	.sample_rate = 1, // -s --sample-rate
	.top_stacks = 10, // -T --top
	.min_size = 0, // -z --min-size
	.max_size = -1, // -Z --max-size
	.object = "libc.so.6", // -O --obj
	.percpu = false, // --percpu
	.perf_max_stack_depth = 127,
	.stack_max_entries = 1024,
	.page_size = 1,
	.kernel_trace = true,
	.verbose = false,
	.command = NULL, // -c --command
};

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
	do { \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
				.func_name = #sym_name, \
				.retprobe = is_retprobe); \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
				skel->progs.prog_name, \
				env.pid, \
				env.object, \
				0, \
				&uprobe_opts); \
		if (!skel->links.prog_name) { \
			perror("failed to attach uprobe for " #sym_name); \
			return -errno; \
		} \
		printf("attached uprobe for " #sym_name "with pid %d\n", env.pid); \
	} while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define DISABLE_TRACEPOINT(skel, prog_name) \
	do { \
		if (bpf_program__set_autoload(skel->progs.prog_name, false)) { \
			fprintf(stderr, "failed to set autoload off for kmalloc\n"); \
			return -errno; \
		} \
		printf("set autoload off for " #prog_name"\n"); \
	} while (false)

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace outstanding memory allocations\n"
"\n"
"USAGE: memleak [-h] [-c COMMAND] [-p PID] [-t] [-n] [-a] [-o AGE_MS] [-C] [-F] [-s SAMPLE_RATE] [-T TOP_STACKS] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJECT] [-P PERCPU] [INTERVAL] [INTERVALS]\n"
"\n"
"EXAMPLES:\n"

"./memleak -p $(pidof allocs)"
"        Trace allocations and display a summary of 'leaked' (outstanding)"
"        allocations every 5 seconds"
"./memleak -p $(pidof allocs) -t"
"        Trace allocations and display each individual allocator function call"
"./memleak -ap $(pidof allocs) 10"
"        Trace allocations and display allocated addresses, sizes, and stacks"
"        every 10 seconds for outstanding allocations"
"./memleak -c './allocs'"
"        Run the specified command and trace its allocations"
"./memleak"
"        Trace allocations in kernel mode and display a summary of outstanding"
"        allocations every 5 seconds"
"./memleak -o 60000"
"        Trace allocations in kernel mode and display a summary of outstanding"
"        allocations that are at least one minute (60 seconds) old"
"./memleak -s 5"
"        Trace roughly every 5th allocation, to reduce overhead"
"";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "Process ID to trace. if not specified, trace kernel allocs"},
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call" },
	{"count", 'n', "COUNT", 0, "number of times to print the report before exiting"},
	{"show-allocs", 'a', 0, 0, "show allocation addresses and sizes as well as call stacks"},
	{"older", 'o', "AGE_MS", 0, "prune allocations younger than this age in milliseconds"},
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command"},
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only"},
	{"wa-missing-free", 'F', 0, 0, "Workaround to alleviate misjudgments when free is missing"},
	{"sample-rate", 's', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease the overhead"},
	{"top", 'T', "TOP_STACKS", 0, "display only this many top allocating stacks (by size)"},
	{"min-size", 'z', "MIN_SIZE", 0, "capture only allocations larger than this size"},
	{"max-size", 'Z', "MAX_SIZE", 0, "capture only allocations smaller than this size"},
	{"obj", 'O', "OBJECT", 0, "attach to allocator functions in the specified object"},
	{"percpu", 'P', "PERCPU", 0, "trace percpu allocations"},
	{},
};

static long argp_parse_long(int key, const char *arg, struct argp_state *state)
{
	errno = 0;
	const long temp = strtol(arg, NULL, 10);
	if (errno || temp <= 0) {
		fprintf(stderr, "error arg:%c %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

static error_t argp_parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'p':
		env.pid = atoi(arg);
		printf("parsed pid: %d\n", env.pid);
		break;
	case 't':
		env.trace_all = true;
		puts("arg trace_all");
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'a':
		break;
	case 'O':
		env.object = strdup(arg);
		printf("parsed object: %s\n", env.object);
		break;
	case 'c':
		env.command = strdup(arg);
		printf("parsed command: %s\n", env.command);
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
	case ARGP_KEY_ARG:
		++pos_args;

		if (pos_args == 1) {
			puts("arg interval");
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2) {
			puts("arg nr_intervals");
			env.nr_intervals = argp_parse_long(key, arg, state);
		} else {
			fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		break;
	default:
		fprintf(stderr, "unknown arg:%c %s\n", (char)key, arg);
		return ARGP_ERR_UNKNOWN;
	}

	fprintf(stderr, "good arg:%c %s\n", (char)key, arg);

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static int timer_fd = -1;
static int signal_fd = -1;
static int child_exec_event_fd = -1;

pid_t fork_sync_exec(const char *command, int event_fd)
{
	const pid_t pid = fork();

	switch (pid) {
	case -1:
		perror("failed to create child process");
		break;
	case 0: {
		// todo - any redirection?

		uint64_t event = 0;
		const ssize_t bytes = read(event_fd, &event, sizeof(event));
		if (bytes < 0) {
			perror("failed to read child exec event fd");
			exit(1);
		} else if (bytes != sizeof(event)) {
			fprintf(stderr, "read unexpected size\n");
			exit(1);
		}

		if (event != 1) {
			fprintf(stderr, "received no-go event. exiting child process\n");
			exit(1);
		}

		printf("received go event. executing child command\n");

		const int err = execl(command, "todo - child name", NULL);
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

static int print_stacks(alloc_info_t *allocs, size_t nr_allocs, int stack_traces_fd)
{
	int ret = 0;

	uint64_t *stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
	if (!stack) {
		fprintf(stderr, "failed to alloc stack array\n");
		return -ENOMEM;
	}

	sym_src_cfg src_cfg = {};

	if (env.pid < 0) {
		puts("stacks kernel");
		src_cfg.src_type = SRC_T_KERNEL;
		src_cfg.params.kernel.kallsyms = NULL;
		src_cfg.params.kernel.kernel_image = NULL;
	} else {
		puts("stacks userspace");
		src_cfg.src_type = SRC_T_PROCESS;
		src_cfg.params.process.pid = env.pid;
	}

	for (size_t i = 0; i < nr_allocs; ++i) {
		alloc_info_t *alloc = &allocs[i];

		printf("alloc stack_id:%d, size:%llu\n", alloc->stack_id, alloc->size);

		if (bpf_map_lookup_elem(stack_traces_fd, &alloc->stack_id, stack)) {
			perror("stack lookup fail");
			if (errno == ENOENT || errno == EEXIST) {
				puts("key no longer exists");
				continue;
			}

			perror("failed to lookup stack trace");
			ret =  -errno;
			break;
		}
		puts("stack found");

		const blazesym_result *result = blazesym_symbolize(symbolizer, &src_cfg, 1, stack, env.perf_max_stack_depth);
		printf("blazesym result - size:%lu\n", result->size);

		for (size_t j = 0; result && j < result->size; j++) {
			if (result->entries[j].size == 0)
				continue;

			const blazesym_csym *sym = &result->entries[j].syms[0];

			if (sym->line_no)
				printf("%s:%ld\n", sym->symbol, sym->line_no);
			else
				printf("%s\n", sym->symbol);
		}

		puts("=============");

		blazesym_result_free(result);
	}

	free(stack);

	return ret;
}

static int alloc_size_compare(const void *a, const void *b)
{
	const alloc_info_t *x = (alloc_info_t *)a;
	const alloc_info_t *y = (alloc_info_t *)b;

	// compares for descending order
	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}


static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd)
{
	int ret = 0;

	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	alloc_info_t *allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	if (!allocs) {
		fprintf(stderr, "failed to top allocs array\n");
		return -ENOMEM;
	}

	uint64_t *prev_key = NULL;
	uint64_t curr_key = 0;

	size_t nr_allocs = 0;
	for (;;) {
		alloc_info_t alloc_info = {};
		memset(&alloc_info, 0, sizeof(alloc_info));

		if (bpf_map_get_next_key(allocs_fd, prev_key, &curr_key)) {
			if (errno == ENOENT)
				break; // no more keys

			perror("map get next key error");
			ret = -errno;
			break;
		}

		prev_key = &curr_key;

		if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info)) {
			if (errno == ENOENT)
				continue;

			perror("map lookup error");
			ret = -errno;
			break;
		}

		if (get_ktime_ns() - env.min_age_ns < alloc_info.timestamp_ns) {
			puts("< min_age");
			continue;
		}

		if (alloc_info.stack_id < 0) {
			continue;
		}

		// when the stack_id exists in the allocs array,
		//   increment size with alloc_info.size
		bool alloc_exists = false;

		for (size_t i = 0; !alloc_exists && i < nr_allocs; ++i) {
			if (allocs[i].stack_id == alloc_info.stack_id) {
				allocs[i].size += alloc_info.size;

				alloc_exists = true;
				break;
			}
		}

		if (alloc_exists)
			continue;

		// when the stack_id does not exist in the allocs array,
		//   insert it into the array
		memcpy(&allocs[nr_allocs], &alloc_info, sizeof(alloc_info));
		nr_allocs++;
	}

	// sort the allocs array in descending order
	qsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	nr_allocs = nr_allocs < env.top_stacks ? nr_allocs : env.top_stacks;

	printf("print nr_allocs: %zu\n", nr_allocs);
	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs);

	print_stacks(allocs, nr_allocs, stack_traces_fd);

	free(allocs);

	return ret;
}

int disable_kernel_tracepoints(struct memleak_bpf *skel)
{
	DISABLE_TRACEPOINT(skel, tracepoint__kmalloc);
	DISABLE_TRACEPOINT(skel, tracepoint__kmalloc_node);
	DISABLE_TRACEPOINT(skel, tracepoint__kfree);
	DISABLE_TRACEPOINT(skel, tracepoint__kmem_cache_alloc);
	DISABLE_TRACEPOINT(skel, tracepoint__kmem_cache_alloc_node);
	DISABLE_TRACEPOINT(skel, tracepoint__kmem_cache_free);
	DISABLE_TRACEPOINT(skel, tracepoint__mm_page_alloc);
	DISABLE_TRACEPOINT(skel, tracepoint__mm_page_free);
	DISABLE_TRACEPOINT(skel, tracepoint__percpu_alloc_percpu);
	DISABLE_TRACEPOINT(skel, tracepoint__percpu_free_percpu);

	return 0;
}

int attach_uprobes(struct memleak_bpf *skel)
{
	ATTACH_UPROBE(skel, malloc, malloc_enter);
	ATTACH_URETPROBE(skel, malloc, malloc_exit);

	ATTACH_UPROBE(skel, calloc, calloc_enter);
	ATTACH_URETPROBE(skel, calloc, calloc_exit);

	ATTACH_UPROBE(skel, realloc, realloc_enter);
	ATTACH_URETPROBE(skel, realloc, realloc_exit);

	ATTACH_UPROBE(skel, mmap, mmap_enter);
	ATTACH_URETPROBE(skel, mmap, mmap_exit);

	ATTACH_UPROBE(skel, posix_memalign, posix_memalign_enter);
	ATTACH_URETPROBE(skel, posix_memalign, posix_memalign_exit);

	ATTACH_UPROBE(skel, memalign, memalign_enter);
	ATTACH_URETPROBE(skel, memalign, memalign_exit);

	ATTACH_UPROBE(skel, valloc, valloc_enter); // can fail
	ATTACH_URETPROBE(skel, valloc, valloc_exit); // can fail

	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter); // can fail
	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit); // can fail

	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter); // can fail
	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit); // can fail

	ATTACH_UPROBE(skel, free, free_enter);
	ATTACH_UPROBE(skel, munmap, munmap_enter);

	puts("finished attach_uprobes");

	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = argp_options,
		.parser = argp_parse_arg,
		.doc = argp_args_doc,
	};

	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.min_size > env.max_size) {
		fprintf(stderr, "min size (-z) can't be greater than max_size (-Z)\n");
		return 1;
	}

	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGQUIT);
	sigaddset(&sigset, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &sigset, NULL)) {
		perror("failed to block signal mask");
		return 1;
	}

	signal_fd = signalfd(-1, &sigset, SFD_CLOEXEC);
	if (signal_fd < 0) {
		perror("failed to create signal fd");
		return 1;
	}

	env.page_size = sysconf(_SC_PAGE_SIZE);
	printf("page size: %ld\n", env.page_size);

	env.kernel_trace = env.pid < 0 && !env.command;
	printf("kernel trace: %s\n", env.kernel_trace ? "true" : "false");

	if (env.command) {
		if (env.pid >= 0) {
			fprintf(stderr, "cannot specify both command and pid\n");
			goto cleanup;
		}

		child_exec_event_fd = eventfd(0, EFD_CLOEXEC);
		if (child_exec_event_fd < 0) {
			perror("failed to create child exec event fd");
			return 1;
		}
		const pid_t child_pid = fork_sync_exec(env.command, child_exec_event_fd);
		if (child_pid < 0) {
			perror("failed to spawn child process");
			return 1;
		}
		env.pid = child_pid;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	struct memleak_bpf *skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		return 1;
	}

	skel->rodata->pid = env.pid;
	skel->rodata->min_size = env.min_size;
	skel->rodata->max_size = env.max_size;
	skel->rodata->page_size = env.page_size;
	skel->rodata->sample_every_n = env.sample_every_n;
	skel->rodata->trace_all = env.trace_all;
	skel->rodata->kernel_trace = env.kernel_trace;
	skel->rodata->wa_missing_free = env.wa_missing_free;

	bpf_map__set_value_size(skel->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_max_entries);

	if (!env.kernel_trace && disable_kernel_tracepoints(skel)) {
		fprintf(stderr, "failed to disable kernel tracepoints\n");
		goto cleanup;
	}

	if (memleak_bpf__load(skel)) {
		fprintf(stderr, "failed to load bpf object\n");
		goto cleanup;
	}

	int allocs_fd = bpf_map__fd(skel->maps.allocs);
	if (allocs_fd < 0) {
		fprintf(stderr, "failed to get fd for allocs map\n");
		return 1;
	}

	int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);
	if (stack_traces_fd < 0) {
		fprintf(stderr, "failed to get fd for stack_traces map\n");
		return 1;
	}

	if (!env.kernel_trace) {
		if (attach_uprobes(skel)) {
			fprintf(stderr, "failed to attach uprobes\n");
			goto cleanup;
		}
		puts("attached uprobes");
	}

	if (memleak_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach bpf program(s)\n");
		goto cleanup;
	}

	puts("bpf program attached");

	if (env.command) {
		const uint64_t event = 1;
		if (write(child_exec_event_fd, &event, sizeof(event)) != sizeof(event)) {
			perror("failed to write child exec event");
			goto cleanup;
		}
		printf("wrote child exec event\n");
	}

	symbolizer = blazesym_new();

	struct itimerspec timer_spec;
	timer_spec.it_interval.tv_sec= env.interval;
	timer_spec.it_interval.tv_nsec = 0;
	timer_spec.it_value.tv_sec= env.interval;
	timer_spec.it_value.tv_nsec = 0;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (timer_fd < 0) {
		perror("failed to create timerfd");
	}

	if (timerfd_settime(timer_fd, 0, &timer_spec, NULL)) {
		perror("timerfd settime fail");
		return 1;
	}

	printf("timer fd interval set at %d\n", env.interval);

	struct pollfd fds[] = {
		{.fd = timer_fd, .events = POLLIN},
		{.fd = signal_fd, .events = POLLIN},
	};

	const nfds_t nfds = sizeof(fds) / sizeof(struct pollfd);

	int i = 0;

	for (;;) {
		printf("polling\n");

		err = poll(fds, nfds, -1);
		if (err < 0) {
			perror("failed to poll");
			return 1;
		}

		if (fds[0].revents & POLLIN) {
			printf("input on timer fd\n");
			uint64_t buffer = 0;
			if (read(fds[0].fd, &buffer, sizeof(buffer)) != sizeof(buffer)) {
				perror("failed to read timerfd");
				return 1;
			}

			print_outstanding_allocs(allocs_fd, stack_traces_fd);

			if (env.nr_intervals && (++i >= env.nr_intervals)) {
				puts("reached target interval count");
				break;
			}

			fds[0].revents = 0;
		}

		if (fds[1].revents & POLLIN) {
			printf("input on signal fd\n");
			struct signalfd_siginfo buffer = {};
			if (read(fds[1].fd, &buffer, sizeof(buffer)) != sizeof(buffer)) {
				perror("failed to read sig fd");
				return 1;
			}

			print_outstanding_allocs(allocs_fd, stack_traces_fd);

			switch (buffer.ssi_signo) {
			case SIGINT: {
				printf("read SIGINT\n");
				if (env.pid > 0) {
					kill(SIGINT, env.pid);
					int wstatus = 0;
					const pid_t pid = wait(&wstatus);
					printf("reaped pid:%d, status:%d\n", pid, wstatus);
				}

				break;
			}
			case SIGQUIT:
				printf("read SIGQUIT\n");
				break;
			case SIGCHLD: {
				printf("read SIGCHLD\n");
				int wstatus = 0;
				const pid_t pid = wait(&wstatus);
				printf("reaped pid:%d, status:%d\n", pid, wstatus);
				break;
			}
			default:
				printf("other signal\n");
				break;
			}

			fds[1].revents = 0;
			goto cleanup;
		}
	}

	printf("end polling\n");

cleanup:
	blazesym_free(symbolizer);
	memleak_bpf__destroy(skel);
	printf("done\n");
}
