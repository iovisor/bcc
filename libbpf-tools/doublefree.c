/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "doublefree.h"
#include "doublefree.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define STACK_DEPTH 127
#define PERF_BUFFER_PAGES 16
/*
 * Short enough that the target exiting is noticed promptly, since the poll is
 * also where the target's liveness is checked.
 */
#define PERF_POLL_TIMEOUT_MS 1000
#define PERF_DRAIN_TIMEOUT_MS 100
/* Generous bound on the syscalls the dynamic linker needs to map libc. */
#define MAX_STARTUP_SYSCALLS 1024
#define CHECK_FAIL true
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define p_info(fmt, ...) __p(stderr, INFO, "INFO", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...) __p(stderr, WARN, "WARN", fmt, ##__VA_ARGS__)
#define p_err(fmt, ...) __p(stderr, ERROR, "ERROR", fmt, ##__VA_ARGS__)

#define UPROBE_ELEM(func_name, check_fail) \
	{ \
		.link = &obj->links.func_name##_entry, \
		.prog = obj->progs.func_name##_entry, \
		.pid = env.pid, \
		.name = #func_name, \
		.lib_path = libc_path, \
		.is_ret = false, \
		.check = check_fail, \
	},

#define URETPROBE_ELEM(func_name, check_fail) \
	{ \
		.link = &obj->links.func_name##_return, \
		.prog = obj->progs.func_name##_return, \
		.pid = env.pid, \
		.name = #func_name, \
		.lib_path = libc_path, \
		.is_ret = true, \
		.check = check_fail, \
	},

#define UPROBE_ELEMS(func_name, check_fail) \
		UPROBE_ELEM(func_name, check_fail) \
		URETPROBE_ELEM(func_name, check_fail)

struct probe {
	/*
	 * Points at the skeleton's link so destroying the skeleton detaches the
	 * probe; keeping the link only in this array would leak the attachment.
	 */
	struct bpf_link **link;
	struct bpf_program *prog;
	pid_t pid;
	const char *name;
	const char *lib_path;
	bool is_ret;
	bool check;
};

enum log_level {
	INFO,
	WARN,
	ERROR,
};

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	int stack_storage_size;
	int perf_max_stack_depth;
	bool verbose;
	char *command;
} env = {
	.pid = -1,
	.stack_storage_size = MAX_ENTRIES,
	.perf_max_stack_depth = STACK_DEPTH,
	.verbose = false,
	.command = NULL,
};

const char *argp_program_version = "doublefree 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] = "Detect and report double free error.\n"
"\n"
"-c or -p is a mandatory option\n"
"EXAMPLES:\n"
"    doublefree -p 1234             # Detect double free on process id 1234\n"
"    doublefree -c a.out            # Detect double free on a.out\n"
"    doublefree -c 'a.out arg'      # Detect double free on a.out with argument\n";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "pid", 'p', "PID", 0, "Detect double free on the specified process", 0 },
	{ "command", 'c', "COMMAND", 0, "Execute the command and detect double free", 0 },
	{},
};

static struct doublefree_bpf *obj = NULL;
static struct syms *syms = NULL;
static enum log_level log_level = ERROR;
/* Set once the child is running on its own and no longer ptrace-stopped. */
static bool child_detached = false;
static bool child_exited = false;

static void __p(FILE *outstream, enum log_level level, const char *level_str,
		const char *fmt, ...)
{
	va_list ap;
	time_t t;
	struct tm *tm;
	char timebuf[32];

	if (level < log_level)
		return;

	t = time(NULL);
	tm = localtime(&t);
	strftime(timebuf, sizeof(timebuf), "%Y-%b-%d %H:%M:%S", tm);

	va_start(ap, fmt);
	fprintf(outstream, "%s %s ", timebuf, level_str);
	vfprintf(outstream, fmt, ap);
	fprintf(outstream, "\n");
	va_end(ap);
	fflush(outstream);
}

static void set_log_level(enum log_level level)
{
	log_level = level;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			p_err("Invalid PID: %s", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.command = strdup(arg);
		if (!env.command) {
			p_err("Failed to set command: %s", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/*
 * Spawn the command and leave it stopped on the execve() trap. The target has
 * not run a single instruction yet, so the caller can resolve its mappings and
 * attach the uprobes without racing it, and no allocation is missed. Without
 * this the target has to be made to sleep before it allocates anything.
 */
static pid_t fork_exec_stopped(char *cmd)
{
	int i = 0;
	int status = 0;
	const char *delim = " ";
	char **argv = NULL;
	char *ptr = NULL;
	char *filepath = NULL;
	pid_t pid = 0;

	if (!cmd) {
		p_err("Invalid command");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		p_err("Failed to fork: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		/* Child process executes followings */

		/*
		 * Ask to be stopped once execve() has replaced the image, so
		 * the parent can attach before any target code runs.
		 */
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
			p_err("Failed to trace itself: %s", strerror(errno));
			_exit(1);
		}

		/*
		 * The worst-case number of tokens is (strlen + 1) / 2
		 * (single-char args separated by spaces). +1 for the
		 * NULL terminator required by execve().
		 */
		argv = calloc(strlen(cmd) / 2 + 2, sizeof(char *));
		if (!argv) {
			p_err("Failed to allocate memory");
			_exit(1);
		}

		ptr = strtok(cmd, delim);
		if (!ptr) {
			p_err("Invalid command");
			free(argv);
			_exit(1);
		}

		filepath = ptr;
		ptr = strtok(NULL, delim);
		argv[i++] = filepath;
		argv[i++] = ptr;
		do {
			ptr = strtok(NULL, delim);
			argv[i++] = ptr;
		} while (ptr);

		execve(filepath, argv, NULL);
		p_err("Failed to execute %s: %s", filepath, strerror(errno));
		free(argv);
		_exit(1);
	}

	/* Parent process waits for the child to stop on the execve() trap. */
	if (waitpid(pid, &status, 0) < 0) {
		p_err("Failed to wait for %s: %s", cmd, strerror(errno));
		return -1;
	}

	if (!WIFSTOPPED(status)) {
		p_err("Failed to execute %s", cmd);
		return -1;
	}

	return pid;
}

/* Let the target run now that the uprobes are in place. */
static int resume_child(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		p_err("Failed to resume %d: %s", pid, strerror(errno));
		return -1;
	}

	child_detached = true;

	return 0;
}

static bool target_alive(void)
{
	int status = 0;
	pid_t ret;

	if (!env.command) {
		/* Not a child of this process, so ask the kernel about it. */
		if (kill(env.pid, 0) && errno == ESRCH)
			return false;

		return true;
	}

	ret = waitpid(env.pid, &status, WNOHANG);
	if (ret == 0)
		return true;

	child_exited = true;

	return false;
}

/*
 * At the execve() trap the dynamic linker has not mapped libc yet, so step the
 * target by syscall until it shows up. That leaves the target stopped in the
 * middle of dynamic linking, still ahead of any of the program's own code, and
 * unlike a breakpoint on the entry point it needs no architecture-specific trap
 * instruction.
 */
static int wait_lib_loaded(pid_t pid, const char *lib, char *path, size_t path_sz)
{
	int i = 0;
	int sig = 0;
	int status = 0;

	for (i = 0; i < MAX_STARTUP_SYSCALLS; ++i) {
		if (!get_pid_lib_text_path(pid, lib, path, path_sz))
			return 0;

		if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig)) {
			p_err("Failed to step %d: %s", pid, strerror(errno));
			return -1;
		}

		if (waitpid(pid, &status, 0) < 0) {
			p_err("Failed to wait for %d: %s", pid, strerror(errno));
			return -1;
		}

		if (!WIFSTOPPED(status)) {
			p_err("Process %d exited while loading lib%s", pid, lib);
			return -1;
		}

		/* Forward whatever is not the syscall trap itself. */
		sig = WSTOPSIG(status);
		if (sig == SIGTRAP)
			sig = 0;
	}

	p_err("lib%s was not loaded by %d", lib, pid);

	return -1;
}

static int resolve_libc_path(char *path, size_t path_sz)
{
	if (env.command)
		return wait_lib_loaded(env.pid, "c", path, path_sz);

	if (get_pid_lib_text_path(env.pid, "c", path, path_sz)) {
		p_err("Failed to find libc.so in process %d", env.pid);
		return -1;
	}

	return 0;
}

static int attach_uprobe(struct probe *probe)
{
	off_t func_off = get_elf_func_offset(probe->lib_path, probe->name);

	if (probe->check && func_off < 0)
		return -1;

	*probe->link = bpf_program__attach_uprobe(probe->prog,
						  probe->is_ret,
						  probe->pid,
						  probe->lib_path,
						  func_off);
	if (probe->check && !*probe->link) {
		p_err("Failed to attach u[ret]probe %s: %s", probe->name, strerror(errno));
		return -1;
	}

	return 0;
}

static int attach_uprobes(const char *libc_path)
{
	int i = 0;
	int err = 0;
	struct probe probes[] = {
		URETPROBE_ELEM(malloc, CHECK_FAIL)
		UPROBE_ELEM(free, CHECK_FAIL)
		URETPROBE_ELEM(calloc, CHECK_FAIL)
		UPROBE_ELEMS(realloc, CHECK_FAIL)
		UPROBE_ELEMS(posix_memalign, CHECK_FAIL)
		URETPROBE_ELEM(memalign, CHECK_FAIL)

		URETPROBE_ELEM(aligned_alloc, !CHECK_FAIL)
		URETPROBE_ELEM(valloc, !CHECK_FAIL)
		URETPROBE_ELEM(pvalloc, !CHECK_FAIL)
		UPROBE_ELEMS(reallocarray, !CHECK_FAIL)
	};

	for (i = 0; i < ARRAY_SIZE(probes); ++i) {
		err = attach_uprobe(&probes[i]);
		if (err < 0)
			return err;
	}

	return 0;
}

static void print_backtrace(int stackid)
{
	size_t i = 0;
	int err = 0;
	unsigned long *ip = NULL;
	int sfd = bpf_map__fd(obj->maps.stack_traces);
	struct sym_info sinfo = {};

	if (stackid < 0) {
		printf("\t[stack trace unavailable]\n\n");
		return;
	}

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		p_err("Failed to allocate memory");
		return;
	}

	err = bpf_map_lookup_elem(sfd, &stackid, ip);
	if (err < 0) {
		p_err("Failed to lookup stack id %d: %s", stackid, strerror(errno));
		free(ip);
		return;
	}

	for (i = 0; i < env.perf_max_stack_depth && ip[i]; ++i) {
		printf("\t#%zu %#016lx", i + 1, ip[i]);
		err = syms__map_addr_dso(syms, ip[i], &sinfo);
		if (!err) {
			if (sinfo.sym_name)
				printf(" %s+0x%lx (%s+0x%lx)",
				       sinfo.sym_name, sinfo.sym_offset,
				       sinfo.dso_name, sinfo.dso_offset);
			else
				printf(" [unknown] (%s+0x%lx)",
				       sinfo.dso_name, sinfo.dso_offset);
		}
		printf("\n");
	}
	printf("\n");

	free(ip);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;

	printf("\nDouble free detected on %#llx\n", e->addr);

	printf("\nAllocation:\n");
	print_backtrace(e->alloc_stackid);

	printf("First free:\n");
	print_backtrace(e->free_stackid);

	printf("Second free:\n");
	print_backtrace(e->doublefree_stackid);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	p_err("Lost %llu events on CPU #%d!", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	int err = 0;
	int ret = 0;
	char libc_path[PATH_MAX] = {};
	struct syms_cache *syms_cache = NULL;
	struct perf_buffer *pb = NULL;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	set_log_level(INFO);

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.command && env.pid != -1) {
		p_err("Use either -c or -p only");
		ret = -1;
		goto cleanup;
	}

	if (!env.command && env.pid == -1) {
		p_err("-c or -p is a mandatory option");
		ret = -1;
		goto cleanup;
	}

	if (env.command) {
		env.pid = fork_exec_stopped(env.command);
		if (env.pid < 0) {
			p_err("Failed to spawn child process");
			ret = -1;
			goto cleanup;
		}
		p_info("Execute command: %s(pid %d)", env.command, env.pid);
	}

	libbpf_set_print(libbpf_print_fn);

	obj = doublefree_bpf__open();
	if (!obj) {
		p_err("Failed to open BPF object");
		ret = -1;
		goto cleanup;
	}

	bpf_map__set_value_size(obj->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(__u64));
	bpf_map__set_max_entries(obj->maps.stack_traces,
				 env.stack_storage_size);

	err = doublefree_bpf__load(obj);
	if (err) {
		p_err("Failed to load BPF object: %d", err);
		ret = -1;
		goto cleanup;
	}

	/*
	 * With -c this also walks the target up to the point where libc is
	 * mapped, so the uprobes and the symbol cache below both see the real
	 * target image rather than the pre-execve() one.
	 */
	err = resolve_libc_path(libc_path, sizeof(libc_path));
	if (err) {
		ret = -1;
		goto cleanup;
	}

	err = attach_uprobes(libc_path);
	if (err) {
		ret = -1;
		goto cleanup;
	}

	/*
	 * The symbols are pre-set as global variables and used in the event
	 * handler. If a double free error occurs, causing the target process to
	 * terminate, it becomes impossible to obtain symbols from the
	 * terminated process.
	 */
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		p_warn("Failed to load symbol");
	} else {
		syms = syms_cache__get_syms(syms_cache, env.pid);
		if (!syms)
			p_warn("Failed to get symbol");
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		p_err("Failed to open perf buffer: %s", strerror(errno));
		ret = -1;
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		p_err("Failed to set signal handler: %s", strerror(errno));
		ret = -1;
		goto cleanup;
	}

	if (env.command && resume_child(env.pid)) {
		ret = -1;
		goto cleanup;
	}

	printf("Tracing double free... Hit Ctrl-C to stop\n");
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			p_err("Failed to poll perf buffer: %d", err);
			ret = -1;
			break;
		}

		if (!target_alive()) {
			p_info("Target process %d exited", env.pid);
			break;
		}
	}

	/*
	 * A double free usually kills the target, so the report is the last
	 * thing it produces. Drain whatever is still buffered before leaving.
	 */
	perf_buffer__poll(pb, PERF_DRAIN_TIMEOUT_MS);

cleanup:
	perf_buffer__free(pb);
	syms_cache__free(syms_cache);
	doublefree_bpf__destroy(obj);

	if (env.command && env.pid > 0 && !child_exited) {
		/*
		 * The child is ours, so do not leave it running unobserved,
		 * and reap it rather than leaving a zombie behind.
		 */
		if (!child_detached)
			ptrace(PTRACE_DETACH, env.pid, NULL, NULL);

		if (kill(env.pid, SIGTERM))
			p_warn("Failed to signal %d: %s", env.pid, strerror(errno));
		else if (waitpid(env.pid, NULL, 0) < 0)
			p_warn("Failed to reap %d: %s", env.pid, strerror(errno));
	}

	free(env.command);

	return ret;
}
