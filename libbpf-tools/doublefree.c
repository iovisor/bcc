/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright 2022 LG Electronics Inc. */
#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "doublefree.h"
#include "doublefree.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES 16
/*
 * Short enough that the target exiting is noticed promptly, since the poll is
 * also where the target's liveness is checked.
 */
#define PERF_POLL_TIMEOUT_MS 1000
/* Generous bound on the syscalls the dynamic linker needs to map libc. */
#define MAX_STARTUP_SYSCALLS 1024
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define UPROBE(skel, sym, ...)					\
	{							\
		.func = #sym,					\
		.prog = (skel)->progs.sym##_entry,		\
		.link = &(skel)->links.sym##_entry,		\
		##__VA_ARGS__					\
	}

#define URETPROBE(skel, sym, ...)				\
	{							\
		.func = #sym,					\
		.retprobe = true,				\
		.prog = (skel)->progs.sym##_return,		\
		.link = &(skel)->links.sym##_return,		\
		##__VA_ARGS__					\
	}

struct probe {
	/* The libc function the program is attached to. */
	const char *func;
	bool retprobe;
	/* Not every libc has the function, and the tool works without it. */
	bool optional;
	struct bpf_program *prog;
	/*
	 * Points at the skeleton's link so destroying the skeleton detaches the
	 * probe; keeping the link only in this array would leak the attachment.
	 */
	struct bpf_link **link;
};

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	bool verbose;
	char *command;
} env = {
	.pid = -1,
};

const char *argp_program_version = "doublefree 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] = "Detect and report double free error.\n"
"\n"
"-c or -p is a mandatory option\n"
"COMMAND is split on spaces, quoting is not supported\n"
"EXAMPLES:\n"
"    doublefree -p 1234             # Detect double free on process id 1234\n"
"    doublefree -c ./a.out          # Detect double free on a.out\n"
"    doublefree -c './a.out arg'    # Detect double free on a.out with argument\n";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{ "pid", 'p', "PID", 0, "Detect double free on the specified process", 0 },
	{ "command", 'c', "COMMAND", 0, "Execute the command and detect double free", 0 },
	{},
};

static struct doublefree_bpf *obj = NULL;
static struct syms *syms = NULL;
/*
 * The child spawned for -c, for as long as it is ours to stop and reap. Kept
 * apart from env.pid so that a process named with -p is never signalled.
 */
static pid_t child = -1;
/* Set once the child is running on its own and no longer ptrace-stopped. */
static bool child_detached = false;

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
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.command = strdup(arg);
		if (!env.command) {
			warn("failed to set command: %s\n", arg);
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
	const char *delim = " ";
	char **argv = NULL;
	char *token = NULL;
	int argc = 0;
	int status = 0;
	pid_t pid = 0;

	pid = fork();
	if (pid < 0) {
		warn("failed to fork: %s\n", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		/* Child process executes followings */

		/*
		 * Ask to be stopped once execve() has replaced the image, so
		 * the parent can attach before any target code runs.
		 */
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
			warn("failed to trace itself: %s\n", strerror(errno));
			_exit(1);
		}

		/*
		 * Every token but the last is followed by a delimiter, so
		 * there are at most (strlen + 1) / 2 of them. calloc() leaves
		 * the NULL terminator execvp() requires in the extra slot.
		 */
		argv = calloc((strlen(cmd) + 1) / 2 + 1, sizeof(*argv));
		if (!argv) {
			warn("failed to allocate memory\n");
			_exit(1);
		}

		for (token = strtok(cmd, delim); token;
		     token = strtok(NULL, delim))
			argv[argc++] = token;

		if (!argc) {
			warn("empty command\n");
			_exit(1);
		}

		execvp(argv[0], argv);
		warn("failed to execute %s: %s\n", argv[0], strerror(errno));
		_exit(1);
	}

	/* Parent process waits for the child to stop on the execve() trap. */
	if (waitpid(pid, &status, 0) < 0) {
		warn("failed to wait for %s: %s\n", cmd, strerror(errno));
		return -1;
	}

	/*
	 * The child has exited, which waitpid() has just reaped, and has said
	 * itself why it could not get as far as the trap.
	 */
	if (!WIFSTOPPED(status))
		return -1;

	return pid;
}

/* Let the target run now that the uprobes are in place. */
static int resume_child(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		warn("failed to resume %d: %s\n", pid, strerror(errno));
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

	child = -1;

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
			warn("failed to step %d: %s\n", pid, strerror(errno));
			return -1;
		}

		if (waitpid(pid, &status, 0) < 0) {
			warn("failed to wait for %d: %s\n", pid, strerror(errno));
			return -1;
		}

		if (!WIFSTOPPED(status)) {
			/* waitpid() has just reaped it. */
			child = -1;
			warn("process %d exited before loading lib%s\n", pid, lib);
			return -1;
		}

		/* Forward whatever is not the syscall trap itself. */
		sig = WSTOPSIG(status);
		if (sig == SIGTRAP)
			sig = 0;
	}

	warn("lib%s was not loaded by %d\n", lib, pid);

	return -1;
}

static int resolve_libc_path(char *path, size_t path_sz)
{
	if (env.command)
		return wait_lib_loaded(env.pid, "c", path, path_sz);

	if (get_pid_lib_text_path(env.pid, "c", path, path_sz)) {
		warn("failed to find libc in process %d\n", env.pid);
		return -1;
	}

	return 0;
}

static int attach_uprobes(struct doublefree_bpf *skel, pid_t pid,
			  const char *libc_path)
{
	const struct probe probes[] = {
		URETPROBE(skel, malloc),
		UPROBE(skel, free),
		URETPROBE(skel, calloc),
		UPROBE(skel, realloc),
		URETPROBE(skel, realloc),
		UPROBE(skel, posix_memalign),
		URETPROBE(skel, posix_memalign),
		URETPROBE(skel, memalign),

		URETPROBE(skel, aligned_alloc, .optional = true),
		URETPROBE(skel, valloc, .optional = true),
		URETPROBE(skel, pvalloc, .optional = true),
		UPROBE(skel, reallocarray, .optional = true),
		URETPROBE(skel, reallocarray, .optional = true),
	};
	size_t i = 0;
	int err = 0;

	for (i = 0; i < ARRAY_SIZE(probes); ++i) {
		const struct probe *probe = &probes[i];
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
			    .func_name = probe->func,
			    .retprobe = probe->retprobe);

		*probe->link = bpf_program__attach_uprobe_opts(probe->prog, pid,
							       libc_path, 0,
							       &uprobe_opts);
		if (*probe->link)
			continue;

		err = -errno;
		/* libbpf has already said that libc does not have the symbol. */
		if (probe->optional && err == -ENOENT)
			continue;

		warn("failed to attach %s to %s: %s\n",
		     probe->retprobe ? "uretprobe" : "uprobe", probe->func,
		     strerror(-err));
		return err;
	}

	return 0;
}

static void print_backtrace(int stackid)
{
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};
	int sfd = bpf_map__fd(obj->maps.stack_traces);
	struct sym_info sinfo = {};
	size_t i = 0;

	if (stackid < 0) {
		printf("\t[stack trace unavailable]\n\n");
		return;
	}

	if (bpf_map_lookup_elem(sfd, &stackid, ip)) {
		warn("failed to lookup stack id %d: %s\n", stackid, strerror(errno));
		return;
	}

	for (i = 0; i < PERF_MAX_STACK_DEPTH && ip[i]; ++i) {
		unsigned long addr = ip[i];

		printf("\t#%zu 0x%016lx", i + 1, addr);
		/* Without symbols the bare address is all there is to print. */
		if (syms && !syms__map_addr_dso(syms, addr, &sinfo)) {
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
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	int err = 0;
	char libc_path[PATH_MAX] = {};
	struct syms_cache *syms_cache = NULL;
	struct perf_buffer *pb = NULL;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.command && env.pid != -1) {
		warn("use either -c or -p only\n");
		err = -EINVAL;
		goto cleanup;
	}

	if (!env.command && env.pid == -1) {
		warn("-c or -p is a mandatory option\n");
		err = -EINVAL;
		goto cleanup;
	}

	if (env.command) {
		env.pid = fork_exec_stopped(env.command);
		if (env.pid < 0) {
			err = -1;
			goto cleanup;
		}
		child = env.pid;
		printf("Execute command: %s(pid %d)\n", env.command, env.pid);
	}

	libbpf_set_print(libbpf_print_fn);

	obj = doublefree_bpf__open_and_load();
	if (!obj) {
		warn("failed to open and load BPF object\n");
		err = -1;
		goto cleanup;
	}

	/*
	 * With -c this also walks the target up to the point where libc is
	 * mapped, so the uprobes and the symbol cache below both see the real
	 * target image rather than the pre-execve() one.
	 */
	err = resolve_libc_path(libc_path, sizeof(libc_path));
	if (err)
		goto cleanup;

	err = attach_uprobes(obj, env.pid, libc_path);
	if (err)
		goto cleanup;

	/*
	 * The symbols are pre-set as global variables and used in the event
	 * handler. If a double free error occurs, causing the target process to
	 * terminate, it becomes impossible to obtain symbols from the
	 * terminated process.
	 */
	syms_cache = syms_cache__new(0);
	if (syms_cache)
		syms = syms_cache__get_syms(syms_cache, env.pid);
	if (!syms)
		warn("failed to load symbols of %d, reporting bare addresses\n",
		     env.pid);

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = -errno;
		warn("failed to set signal handler: %s\n", strerror(-err));
		goto cleanup;
	}

	if (env.command) {
		err = resume_child(env.pid);
		if (err)
			goto cleanup;
	}

	printf("Tracing double free... Hit Ctrl-C to stop\n");
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("failed to poll perf buffer: %s\n", strerror(-err));
			break;
		}
		/* reset err to return 0 if exiting */
		err = 0;

		if (!target_alive()) {
			printf("Target process %d exited\n", env.pid);
			break;
		}
	}

	/*
	 * A double free usually kills the target, so the report is the last
	 * thing it produces. Consume whatever is still buffered before leaving.
	 */
	perf_buffer__consume(pb);

cleanup:
	perf_buffer__free(pb);
	syms_cache__free(syms_cache);
	doublefree_bpf__destroy(obj);

	if (child > 0) {
		/*
		 * The child is ours, so do not leave it running unobserved,
		 * and reap it rather than leaving a zombie behind.
		 */
		if (!child_detached)
			ptrace(PTRACE_DETACH, child, NULL, NULL);

		if (kill(child, SIGTERM))
			warn("failed to signal %d: %s\n", child, strerror(errno));
		else if (waitpid(child, NULL, 0) < 0)
			warn("failed to reap %d: %s\n", child, strerror(errno));
	}

	free(env.command);

	return err != 0;
}
