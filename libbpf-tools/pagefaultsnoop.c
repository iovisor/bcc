/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Copyright (c) 2022 Rong Tao
 *
 * 06-Jan-2022		Rong Tao   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pagefaultsnoop.h"
#include "pagefaultsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

enum vm_fault_reason {
	VM_FAULT_OOM            = 0x000001,
	VM_FAULT_SIGBUS         = 0x000002,
	VM_FAULT_MAJOR          = 0x000004,
	VM_FAULT_WRITE          = 0x000008,
	VM_FAULT_HWPOISON       = 0x000010,
	VM_FAULT_HWPOISON_LARGE = 0x000020,
	VM_FAULT_SIGSEGV        = 0x000040,
	VM_FAULT_NOPAGE         = 0x000100,
	VM_FAULT_LOCKED         = 0x000200,
	VM_FAULT_RETRY          = 0x000400,
	VM_FAULT_FALLBACK       = 0x000800,
	VM_FAULT_DONE_COW       = 0x001000,
	VM_FAULT_NEEDDSYNC      = 0x002000,
	VM_FAULT_HINDEX_MASK    = 0x0f0000,
};

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static pid_t target_pid = 0;
static bool ignore_errors = false;
static bool verbose = false;
static bool with_flag = false;
static enum vm_fault_reason opt_flag = 0;
static struct hist zero;

const char *argp_program_version = "pagefaultsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace page fault.\n"
"\n"
"USAGE: pagefaultsnoop [-h] [-t] [-x] [-p PID] [-F flag]\n"
"\n"
"EXAMPLES:\n"
"    pagefaultsnoop             # trace page fault\n"
"    pagefaultsnoop -t          # include timestamps\n"
"    pagefaultsnoop -x          # ignore errors on output\n"
"    pagefaultsnoop -p 1216     # only trace PID 1216\n"
"    pagefaultsnoop -F RETRY    # only trace VM_FAULT_RETRY page fault\n"
"\n"
"VM_FAULT options are reported as:\n"
"  VM_FAULT_OOM                    O.............\n"
"  VM_FAULT_SIGBUS                 .S............\n"
"  VM_FAULT_MAJOR                  ..M...........\n"
"  VM_FAULT_WRITE                  ...W..........\n"
"  VM_FAULT_HWPOISON               ....h.........\n"
"  VM_FAULT_HWPOISON_LARGE         .....H........\n"
"  VM_FAULT_SIGSEGV                ......V.......\n"
"  VM_FAULT_NOPAGE                 .......N......\n"
"  VM_FAULT_LOCKED                 ........L.....\n"
"  VM_FAULT_RETRY                  .........R....\n"
"  VM_FAULT_FALLBACK               ..........F...\n"
"  VM_FAULT_DONE_COW               ...........C..\n"
"  VM_FAULT_NEEDDSYNC              ............s.\n"
"  VM_FAULT_HINDEX_MASK            .............m\n"
"\n"
"Flag option [-F flag]:\n"
"  flag is one of the VM_FAULT without VM_FAULT_ prefix";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "failed", 'x', NULL, 0, "Include errors on output." },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "flag", 'F', "FLAG", 0, "Only trace FLAG page fault" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static const struct {
	enum vm_fault_reason fault;
	char *name;
} opt_flags[] = {
#define DEF_FLAG(f) {VM_FAULT_##f, #f}
	DEF_FLAG(OOM),
	DEF_FLAG(SIGBUS),
	DEF_FLAG(MAJOR),
	DEF_FLAG(WRITE),
	DEF_FLAG(HWPOISON),
	DEF_FLAG(HWPOISON_LARGE),
	DEF_FLAG(NOPAGE),
	DEF_FLAG(LOCKED),
	DEF_FLAG(RETRY),
	DEF_FLAG(FALLBACK),
	DEF_FLAG(DONE_COW),
	DEF_FLAG(NEEDDSYNC),
	DEF_FLAG(HINDEX_MASK),
	DEF_FLAG(SIGBUS),
#undef DEF_FLAG
	{0,0}
};

static char *pf_type_names[] = {
	"FILE", "ANON", "SWAP", "NUMA", "WRITE"
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;
	int i = 0;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'F':
		with_flag = true;
		while (opt_flags[i].fault) {
			if (strcmp(opt_flags[i].name, arg) == 0) {
				opt_flag = opt_flags[i].fault;
				break;
			}
			i++;
		}
		if (opt_flag == 0) {
			warn("Invalid -F flag: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'x':
		ignore_errors = true;
		break;
	case 't':
		emit_timestamp = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	if (ignore_errors && with_flag) {
		warn("Can't set the -x and -F options at the same time.\n");
		argp_usage(state);
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct pagefault_event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];
	char vm_faults[] = {'O', 'S', 'M', 'W', 'h', 'H', 'V', 'N', 'L', 'R', 'F', 'C', 's', 'm', '\0'};
	enum vm_fault_reason reasons[] = {
		VM_FAULT_OOM,
		VM_FAULT_SIGBUS,
		VM_FAULT_MAJOR,
		VM_FAULT_WRITE,
		VM_FAULT_HWPOISON,
		VM_FAULT_HWPOISON_LARGE,
		VM_FAULT_SIGSEGV,
		VM_FAULT_NOPAGE,
		VM_FAULT_LOCKED,
		VM_FAULT_RETRY,
		VM_FAULT_FALLBACK,
		VM_FAULT_DONE_COW,
		VM_FAULT_NEEDDSYNC,
		VM_FAULT_HINDEX_MASK,
	};
	const char *type;
	int i = 0;

	if (with_flag && opt_flag) {
		if (! (e->vm_fault & opt_flag))
			return;
	}
	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}
	if (e->pf_type == PF_TYPE_FILE)
		type = "FILE";
	else if (e->pf_type == PF_TYPE_ANON)
		type = "ANON";
	else if (e->pf_type == PF_TYPE_SWAP)
		type = "SWAP";
	else if (e->pf_type == PF_TYPE_NUMA)
		type = "NUMA";
	else if (e->pf_type == PF_TYPE_WRITE)
		type = "WRITE";
	else
		type = "UNKN";
	while (vm_faults[i]) {
		if (!(reasons[i] & e->vm_fault)) {
			vm_faults[i] = '.';
		}
		i++;
	}
	printf("%-7d %-16s %-5s %-15s %#016lx %-5lld\n",
	       e->pid, e->task, type, vm_faults, e->address, e->delta);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static int print_hists(struct pagefaultsnoop_bpf__bss *bss)
{
    const char *units = "nsecs";
    pf_type_enum pf_type; 

    for (pf_type = PF_TYPE_FILE; pf_type < PF_TYPE_MAX; pf_type++) {
        struct hist hist = bss->hists[pf_type];

        bss->hists[pf_type] = zero;
        if (!memcmp(&zero, &hist, sizeof(hist)))
            continue;
        printf("operation = '%s'\n", pf_type_names[pf_type]);
        print_log2_hist(hist.slots, MAX_SLOTS, units);
        printf("\n");
    }   
    return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct pagefaultsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	obj = pagefaultsnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->ignore_errors = ignore_errors;

	err = pagefaultsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = pagefaultsnoop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing Pagefault, Ctrl-C to end.\n");
	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-5s %-15s %-18s %-5s\n",
	       "PID", "COMM", "TYPE", "VM_FAULT", "ADDR", "NSEC");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	printf("Cleanup, output latency hists.\n");
	print_hists(obj->bss);
	perf_buffer__free(pb);
	pagefaultsnoop_bpf__destroy(obj);

	return err != 0;
}
