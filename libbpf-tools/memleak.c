#include <argp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/types.h>
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

#define TASK_COMM_LEN 16

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env {
	pid_t pid;
	bool trace_all;
	int interval;
	int count;
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
	char command[TASK_COMM_LEN];
} env = {
	.pid = -1, // -p --pid
	.trace_all = false, // -t --trace
	.interval = 5, // posarg 1
	.count = 0, // posarg 2
	.show_allocs = false, // -a --show-allocs
	.combined_only = false, // --combined-only
	.min_age_ns = 500, // -o --older val * 1e6
	.wa_missing_free = false, // --wa-missing-free
	.sample_rate = 1, // -s --sample-rate
	.top_stacks = 10, // -T --top
	.min_size = 0, // -z --min-size
	.max_size = -1, // -Z --max-size
	// object // -O --obj
	.percpu = false, // --percpu
	.perf_max_stack_depth = 127,
	.stack_max_entries = 1024,
	.page_size = 1,
	.kernel_trace = true,
	.verbose = false,
	.command = {}, // -c --command
};

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: opensnoop [-h] [-T] [-U] [-x] [-p PID] [-t TID] [-u UID] [-d DURATION]\n"
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
	{"older", 'O', "AGE_MS", 0, "prune allocations younger than this age in milliseconds"},
	{"command", 'c', "COMMAND", 0, "execute and trace the specified command"},
	{"combined-only", 'C', 0, 0, "show combined allocation statistics only"},
	{"wa-missing-free", 'F', 0, 0, "Workaround to alleviate misjudgments when free is missing"},
	{"sample-rate", 's', "SAMPLE_RATE", 0, "sample every N-th allocation to decrease the overhead"},
	{"top", 'T', "TOP", 0, "display only this many top allocating stacks (by size)"},
	{"min-size", 'z', "MIN_SIZE", 0, "capture only allocations larger than this size"},
	{"max-size", 'Z', "MAX_SIZE", 0, "capture only allocations smaller than this size"},
	{"obj", 'O', "OBJ", 0, "attach to allocator functions in the specified object"}, // note - default="c" in original bcc
	{"percpu", 'x', 0, 0, "trace percpu allocations"},
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
		puts("arg pid");
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 't':
		puts("arg trace_all");
		env.trace_all = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'a':
		break;
	case 'O':
		env.min_age_ns = 1e6 * argp_parse_long(key, arg, state);
		break;
	case 'c':
		strncpy(env.command, arg, sizeof(env.command));
		printf("parsed command: %s\n", env.command);
		break;
	case 'T':
		env.top_stacks = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		++pos_args;

		if (pos_args == 1) {
			puts("arg interval");
			env.interval = argp_parse_long(key, arg, state);
		}
		else if (pos_args == 2) {
			puts("arg count");
			env.count = argp_parse_long(key, arg, state);
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
		break;
	}

	return pid;
}

static int print_outstanding_allocs(int allocs_fd, int stack_traces_fd)
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	printf("[%d:%d:%d] Top %d stacks with outstanding allocations:\n",
			tm->tm_hour, tm->tm_min, tm->tm_sec, env.top_stacks);

	uint64_t *stack = calloc(env.perf_max_stack_depth, sizeof(*stack));
	if (!stack) {
		fprintf(stderr, "failed to alloc stack\n");
		return -1;
	}

	alloc_info_t alloc_info = {};
	uint64_t *prev_key = NULL;
	uint64_t curr_key = 0;

	for (; !bpf_map_get_next_key(allocs_fd, prev_key, &curr_key); prev_key = &curr_key) {
		if (bpf_map_lookup_elem(allocs_fd, &curr_key, &alloc_info)) {
			perror("map lookup error");
			return -1;
		}

		if (get_ktime_ns() - env.min_age_ns < alloc_info.timestamp_ns) {
			puts("< min_age");
			continue;
		}

		if (alloc_info.stack_id < 0) {
			continue;
		}

		if (bpf_map_lookup_elem(stack_traces_fd, &alloc_info.stack_id, stack)) {
			fprintf(stderr, "failed to lookup stack trace\n");
			free(stack);
			return -1;
		}

		printf("\taddr = %p size = %llu\n", (void *)curr_key, alloc_info.size);

		sym_src_cfg src_cfg = {};

		if (env.pid < 0) {
			src_cfg.src_type = SRC_T_KERNEL;
			src_cfg.params.kernel.kallsyms = NULL;
			src_cfg.params.kernel.kernel_image = NULL;
		} else {
			src_cfg.src_type = SRC_T_PROCESS;
			src_cfg.params.process.pid = env.pid;
		}

		const blazesym_result *result = NULL;
		const blazesym_csym *sym;
		int i, j;
		result = blazesym_symbolize(symbolizer, &src_cfg, 1, stack, env.perf_max_stack_depth);

		for (i = 0; result && i < result->size; i++) {
			if (result->entries[i].size == 0)
				continue;
			sym = &result->entries[i].syms[0];

			if (sym->line_no)
				printf("%s:%ld\n", sym->symbol, sym->line_no);
			else
				printf("%s\n", sym->symbol);
		}

		blazesym_result_free(result);
	}

	free(stack);

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

	if (strlen(env.command)) {
		env.kernel_trace = false;

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

		printf("running command: %s\n", env.command);
	}
	else if (env.pid == -1)
		env.kernel_trace = true;

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

	if (memleak_bpf__load(skel)) {
		fprintf(stderr, "failed to load bpf object\n");
		goto cleanup;
	}

	if (strlen(env.command)) {
		const uint64_t event = 1;
		if (write(child_exec_event_fd, &event, sizeof(event)) != sizeof(event)) {
			perror("failed to write child exec event");
			goto cleanup;
		}
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

	if (memleak_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach bpf program(s)\n");
		goto cleanup;
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

			if (env.count && (++i >= env.count)) {
				puts("reached target count");
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

			switch (buffer.ssi_signo) {
			case SIGINT:
				printf("read SIGINT\n");
				break;
			case SIGQUIT:
				printf("read SIGQUIT\n");
				break;
			case SIGCHLD:
				printf("read SIGCHLD\n");
				// todo - reap
				break;
			default:
				printf("other signal\n");
				break;
			}

			fds[1].revents = 0;
			goto cleanup;
		}

		printf("poll ok\n");
	}

	printf("end polling\n");

cleanup:
	blazesym_free(symbolizer);
	memleak_bpf__destroy(skel);
	printf("done\n");
}
