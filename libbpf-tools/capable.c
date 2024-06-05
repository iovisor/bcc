// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on capable(8) from BCC by Brendan Gregg.
//
// Copyright 2022 Sony Group Corporation

#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <bpf/bpf.h>
#include "capable.h"
#include "capable.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static struct env {
	bool	verbose;
	char	*cgroupspath;
	bool	cg;
	bool	extra_fields;
	bool	user_stack;
	bool	kernel_stack;
	bool	unique;
	char	*unique_type;
	int	stack_storage_size;
	int	perf_max_stack_depth;
	pid_t	pid;
} env = {
	.pid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.unique = false,
};

const char *cap_name[] = {
	[0] = "CAP_CHOWN",
	[1] = "CAP_DAC_OVERRIDE",
	[2] = "CAP_DAC_READ_SEARCH",
	[3] = "CAP_FOWNER",
	[4] = "CAP_FSETID",
	[5] = "CAP_KILL",
	[6] = "CAP_SETGID",
	[7] = "CAP_SETUID",
	[8] = "CAP_SETPCAP",
	[9] = "CAP_LINUX_IMMUTABLE",
	[10] = "CAP_NET_BIND_SERVICE",
	[11] = "CAP_NET_BROADCAST",
	[12] = "CAP_NET_ADMIN",
	[13] = "CAP_NET_RAW",
	[14] = "CAP_IPC_LOCK",
	[15] = "CAP_IPC_OWNER",
	[16] = "CAP_SYS_MODULE",
	[17] = "CAP_SYS_RAWIO",
	[18] = "CAP_SYS_CHROOT",
	[19] = "CAP_SYS_PTRACE",
	[20] = "CAP_SYS_PACCT",
	[21] = "CAP_SYS_ADMIN",
	[22] = "CAP_SYS_BOOT",
	[23] = "CAP_SYS_NICE",
	[24] = "CAP_SYS_RESOURCE",
	[25] = "CAP_SYS_TIME",
	[26] = "CAP_SYS_TTY_CONFIG",
	[27] = "CAP_MKNOD",
	[28] = "CAP_LEASE",
	[29] = "CAP_AUDIT_WRITE",
	[30] = "CAP_AUDIT_CONTROL",
	[31] = "CAP_SETFCAP",
	[32] = "CAP_MAC_OVERRIDE",
	[33] = "CAP_MAC_ADMIN",
	[34] = "CAP_SYSLOG",
	[35] = "CAP_WAKE_ALARM",
	[36] = "CAP_BLOCK_SUSPEND",
	[37] = "CAP_AUDIT_READ",
	[38] = "CAP_PERFMON",
	[39] = "CAP_BPF",
	[40] = "CAP_CHECKPOINT_RESTORE"
};

static volatile sig_atomic_t exiting = 0;
struct syms_cache *syms_cache = NULL;
struct ksyms *ksyms = NULL;
int ifd, sfd;

const char *argp_program_version = "capable 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace security capability checks (cap_capable()).\n"
"\n"
"USAGE: capable [--help] [-p PID | -c CG | -K | -U | -x] [-u TYPE]\n"
"[--perf-max-stack-depth] [--stack-storage-size]\n"
"\n"
"EXAMPLES:\n"
"    capable                  # Trace capability checks\n"
"    capable -p 185           # Trace this PID only\n"
"    capable -c CG            # Trace process under cgroupsPath CG\n"
"    capable -K               # Add kernel stacks to trace\n"
"    capable -x               # Extra fields: show TID and INSETID columns\n"
"    capable -U               # Add user-space stacks to trace\n"
"    capable -u TYPE          # Print unique output for TYPE=[pid | cgroup] (default:off)\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "kernel-stack", 'K', NULL, 0, "output kernel stack trace", 0 },
	{ "user-stack", 'U', NULL, 0, "output user stack trace", 0 },
	{ "extra-fields", 'x', NULL, 0, "extra fields: show TID and INSETID columns", 0 },
	{ "unique", 'u', "off", 0, "Print unique output for <pid> or <cgroup> (default:off)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

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
		if (errno || env.pid == 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'U':
		env.user_stack = true;
		break;
	case 'K':
		env.kernel_stack = true;
		break;
	case 'x':
		env.extra_fields = true;
		break;
	case 'u':
		env.unique_type = arg;
		env.unique = true;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno || env.perf_max_stack_depth == 0) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno || env.stack_storage_size == 0) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void print_map(struct ksyms *ksyms, struct syms_cache *syms_cache)
{
	struct key_t lookup_key = {}, next_key;
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	struct sym_info sinfo;
	int idx;
	int err, i;
	unsigned long *ip;
	struct cap_event val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
		idx = 0;

		err = bpf_map_lookup_elem(ifd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			goto cleanup;
		}
		lookup_key = next_key;

		if (env.kernel_stack) {
			if (bpf_map_lookup_elem(sfd, &next_key.kern_stack_id, ip) != 0)
				fprintf(stderr, "    [Missed Kernel Stack]\n");
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
				ksym = ksyms__map_addr(ksyms, ip[i]);
				if (!env.verbose) {
					printf("    %s\n", ksym ? ksym->name : "Unknown");
				} else {
					if (ksym)
						printf("    #%-2d 0x%lx %s+0x%lx\n", idx++, ip[i], ksym->name, ip[i] - ksym->addr);
					else
						printf("    #%-2d 0x%lx [unknown]\n", idx++, ip[i]);
				}
			}
		}

		if (env.user_stack) {
			if (next_key.user_stack_id == -1)
				goto skip_ustack;

			if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
				fprintf(stderr, "    [Missed User Stack]\n");
				continue;
			}

			syms = syms_cache__get_syms(syms_cache, next_key.tgid);
			if (!syms) {
				fprintf(stderr, "failed to get syms\n");
				goto skip_ustack;
			}
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
				if (!env.verbose) {
					sym = syms__map_addr(syms, ip[i]);
					if (sym)
						printf("    %s\n", sym->name);
					else
						printf("    [unknown]\n");
				} else {
					err = syms__map_addr_dso(syms, ip[i], &sinfo);
					printf("    #%-2d 0x%016lx", idx++, ip[i]);
					if (err == 0) {
						if (sinfo.sym_name)
							printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
						printf(" (%s+0x%lx)", sinfo.dso_name, sinfo.dso_offset);
					}
					printf("\n");
				}
			}
		}

	skip_ustack:
		printf("    %-16s %s (%d)\n", "-", val.task, next_key.pid);
	}

cleanup:
	free(ip);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct cap_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	char *verdict = "deny";
	if (!e->ret)
		verdict = "allow";

	if (env.extra_fields)
		printf("%-8s %-5d %-7d %-7d %-16s %-7d %-20s %-7d %-7s %-7d\n", ts, e->uid, e->pid, e->tgid, e->task, e->cap, cap_name[e->cap], e->audit, verdict, e->insetid);
	else
		printf("%-8s %-5d %-7d %-16s %-7d %-20s %-7d %-7s\n", ts, e->uid, e->pid, e->task, e->cap, cap_name[e->cap], e->audit, verdict);

	print_map(ksyms, syms_cache);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct capable_bpf *obj;
	struct perf_buffer *pb = NULL;
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;
	enum uniqueness uniqueness_type = UNQ_OFF;
	pid_t my_pid = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.unique) {
		if (strcmp(env.unique_type, "pid") == 0) {
			uniqueness_type = UNQ_PID;
		} else if (strcmp(env.unique_type, "cgroup") == 0) {
			uniqueness_type = UNQ_CGROUP;
		} else {
			fprintf(stderr, "Unknown unique type %s\n", env.unique_type);
			return -1;
		}
	}

	libbpf_set_print(libbpf_print_fn);

	obj = capable_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->filter_cg = env.cg;
	obj->rodata->user_stack = env.user_stack;
	obj->rodata->kernel_stack = env.kernel_stack;
	obj->rodata->unique_type = uniqueness_type;

	my_pid = getpid();
	obj->rodata->my_pid = my_pid;

	bpf_map__set_value_size(obj->maps.stackmap, env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

	err = capable_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr, "Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	ifd = bpf_map__fd(obj->maps.info);
	sfd = bpf_map__fd(obj->maps.stackmap);

	err = capable_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
					handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.extra_fields)
		printf("%-8s %-5s %-7s %-7s %-16s %-7s %-20s %-7s %-7s %-7s\n", "TIME", "UID", "PID", "TID", "COMM", "CAP", "NAME", "AUDIT", "VERDICT", "INSETID");
	else
		printf("%-8s %-5s %-7s %-16s %-7s %-20s %-7s %-7s\n", "TIME", "UID", "PID", "COMM", "CAP", "NAME", "AUDIT", "VERDICT");

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	capable_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
