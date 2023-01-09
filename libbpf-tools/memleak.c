#include <argp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include "memleak.skel.h"

#define TASK_COMM_LEN 16

static struct env {
	pid_t pid;
	char command[TASK_COMM_LEN];
	bool kernel_trace;
	bool trace_all;
	//bool show_allocs;
	//bool combined_only;
	int interval;
	int min_age_ns;
	int sample_every_n;
	int sample_rate;
	int num_prints;
	int top_stacks;
	size_t min_size;
	size_t max_size;
	char *object;

	int count;
	bool wa_missing_free;
	bool percpu;
} env;

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";

const char argp_args_doc[] = "trace mem leaks\n"
"\n";

static const struct argp_option argp_options[] = {
	// name/longopt:str, key/shortopt:int, arg:str, flags:int, doc:str
	{"pid", 'p', "PID", 0, "Process ID to trace. if not specified, trace kernel allocs"},
	{"trace", 't', 0, 0, "print trace messages for each alloc/free call" },
	{"interval", 'i', "INTERVAL", 5, "interval in seconds to print outstanding allocs"},
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
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'n':
		env.num_prints = argp_parse_long(key, arg, state);
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
	case ARGP_KEY_ARG:
		++pos_args;

		if (pos_args == 1)
			env.interval = argp_parse_long(key, arg, state);
		else if (pos_args == 2)
			env.num_prints = argp_parse_long(key, arg, state);
		else {
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
	return vfprintf(stderr, format, args);
}

static int timer_fd = -1;
static int signal_fd = -1;
static int child_exec_event_fd = -1;

pid_t spawn_and_wait_on_event(const char *command, int event_fd)
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

	if (strcmp(env.command, "\0") != 0) {
		child_exec_event_fd = eventfd(0, EFD_CLOEXEC);
		if (child_exec_event_fd < 0) {
			perror("failed to create child exec event fd");
			return 1;
		}

		const pid_t child_pid = spawn_and_wait_on_event(env.command, child_exec_event_fd);
		if (child_pid < 0) {
			perror("failed to spawn child process");
			return 1;
		}

		printf("running command: %s\n", env.command);
	}
	else if (env.pid == -1)
		env.kernel_trace = true;

	//libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	//libbpf_set_print(libbpf_print_fn);

	//struct memleak_bpf *skel = memleak_bpf__open();
	//if (!skel) {
	//	fprintf(stderr, "failed to open bpf object\n");
	//	return 1;
	//}

	//skel->rodata->pid = env.pid;
	//skel->rodata->min_size = env.min_size;
	//skel->rodata->max_size = env.max_size;
	//skel->rodata->page_size = 0; // todo - default?
	//skel->rodata->sample_every_n = env.sample_every_n;
	//skel->rodata->trace_all = env.trace_all;
	//skel->rodata->kernel_trace = env.kernel_trace;
	//skel->rodata->wa_missing_free = env.wa_missing_free;

	//if (memleak_bpf__load(skel)) {
	//	fprintf(stderr, "failed to load bpf object\n");
	//	goto cleanup;
	//}

	if (strcmp(env.command, "\0") != 0) {
		const uint64_t event = 1;
		const ssize_t bytes = write(child_exec_event_fd, &event, sizeof(event));
		if (bytes < 0) {
			perror("failed to write child exec event");
			goto cleanup;
		}
	}

	//if (memleak_bpf__attach(skel)) {
	//	fprintf(stderr, "failed to attach bpf program(s)\n");
	//	goto cleanup;
	//}

	struct itimerspec timer_spec;
	timer_spec.it_interval.tv_sec= env.interval;
	timer_spec.it_interval.tv_nsec = 0;
	timer_spec.it_value.tv_sec= env.interval;
	timer_spec.it_value.tv_nsec = 0;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (timer_fd < 0) {
		perror("failed to create timerfd");
	}

	if (timerfd_settime(timer_fd, 0, &timer_spec, NULL)) {
		perror("timerfd settime fail");
		return 1;
	}

	printf("timer fd interval set at %d\n", env.interval);

	printf("begin polling\n");

	struct pollfd fds[] = {
		{.fd = timer_fd, .events = POLLIN},
		{.fd = signal_fd, .events = POLLIN},
	};

	const nfds_t nfds = sizeof(fds) / sizeof(struct pollfd);

	for (;;) {
		err = poll(fds, nfds, -1);
		if (err < 0) {
			perror("failed to poll");
			return 1;
		}

		if (fds[0].revents & POLLIN) {
			printf("input on timer fd\n");
			uint64_t buffer = 0;
			read(fds[0].fd, &buffer, sizeof(buffer));
			fds[0].revents = 0;
		}

		if (fds[1].revents & POLLIN) {
			printf("input on signal fd\n");
			struct signalfd_siginfo buffer = {};
			read(fds[1].fd, &buffer, sizeof(buffer));

			switch (buffer.ssi_signo) {
			case SIGINT:
				printf("read SIGINT\n");
				break;
			case SIGQUIT:
				printf("read SIGQUIT\n");
				break;
			case SIGCHLD:
				printf("read SIGCHLD\n");
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
	//memleak_bpf__destroy(skel);
	printf("done\n");
}
