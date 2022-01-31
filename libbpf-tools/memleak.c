/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022 Jackie Dinh */
/* Based on memleak(8) from BCC by Sasha Goldshtein */
#include <argp.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PATH_MAX	4096

#define INIT_UPROBE(name, pid, path, sym) \
{\
	off_t addr = get_elf_func_offset(path,sym);\
	if (addr < 0) {\
		fprintf(stderr, "cannot get offset of %s (libc: %s)\n", sym, path);\
		goto cleanup;\
	}\
	skel->links.uprobe_##name = bpf_program__attach_uprobe(skel->progs.uprobe_##name, \
							false, pid, path, addr);\
	err = libbpf_get_error(skel->links.uprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
}

#define INIT_URETPROBE(name, pid, path, sym) \
{\
	off_t addr = get_elf_func_offset(path,sym);\
	if (addr < 0) {\
		fprintf(stderr, "cannot get offset of %s (libc: %s)\n", sym, path);\
		goto cleanup;\
	}\
	skel->links.uretprobe_##name = bpf_program__attach_uprobe(skel->progs.uretprobe_##name, \
							true, pid, path, addr);\
	err = libbpf_get_error(skel->links.uretprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uretprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
}

#define INIT_UPROBE_URETPROBE(name, pid, path, sym) \
{\
	off_t addr = get_elf_func_offset(path,sym);\
	if (addr < 0) {\
		fprintf(stderr, "cannot get offset of %s (libc: %s)\n", sym, path);\
		goto cleanup;\
	}\
	skel->links.uprobe_##name = bpf_program__attach_uprobe(skel->progs.uprobe_##name, \
							false, pid, path, addr);\
	err = libbpf_get_error(skel->links.uprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
	skel->links.uretprobe_##name = bpf_program__attach_uprobe(skel->progs.uretprobe_##name, \
							true, pid, path, addr);\
	err = libbpf_get_error(skel->links.uretprobe_##name);\
	if (err) { \
		fprintf(stderr, "Failed to attach uretprobe_##name: %d\n", err); \
		goto cleanup; \
	} \
}

static struct env {
	bool	print_help;
	int64_t	pid;
	int64_t	child_pid;
	bool	trace_all;
	int	interval;
	int	count;
	bool	show_allocs;
	uint64_t	min_age_ns;
	char	*command;
	bool	combined_only;
	bool	wa_missing_free;
	int	sample_rate;
	int	top;
	int	min_size;
	int	max_size;
	char	*obj;
	bool	percpu;
	bool	kernel_trace;
	int	max_stack_depth;
	bool	verbose;
} env = {
	.interval = 5,
	.min_age_ns = 500 * 1e6,
	.sample_rate = 1,
	.top = 10,
	.max_stack_depth = 127,
};

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace and display outstanding allocations to detect\n"
"memory leaks in user-mode processes and the kernel.\n"
"\n"
"USAGE: memleak [-h] [-p PID] [-t] [-a] [-o OLDER] [-c COMMAND]\n"
"                [--combined-only] [--wa-missing-free] [-s SAMPLE_RATE]\n"
"                [-T TOP] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJ]\n"
"                [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"\n"
"./memleak -p $(pidof allocs)\n"
"        Trace allocations and display a summary of \"leaked\" (outstanding)\n"
"        allocations every 5 seconds\n"
"./memleak -p $(pidof allocs) -t\n"
"        Trace allocations and display each individual allocator function call\n"
"./memleak -ap $(pidof allocs) 10\n"
"        Trace allocations and display allocated addresses, sizes, and stacks\n"
"        every 10 seconds for outstanding allocations\n"
"./memleak -c \"./allocs\"\n"
"        Run the specified command and trace its allocations\n"
"./memleak\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations every 5 seconds\n"
"./memleak -o 60000\n"
"        Trace allocations in kernel mode and display a summary of outstanding\n"
"        allocations that are at least one minute (60 seconds) old\n"
"./memleak -s 5\n"
"        Trace roughly every 5th allocation, to reduce overhead\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID" },
	{ "trace", 't', NULL, 0, "Print trace message for each alloc/free call" },
	{ "show-allocs", 'a', NULL, 0, "Show allocation addresses and sizes as well as call stacks" },
	{ "older", 'o', "MILLISECONDS", 0, "Prune allocations younger than this age in milliseconds" },
	{ "command", 'c', "COMMAND", 0, "Execute and trace the specified command" },
	{ "combined-only", 'C', NULL, 0, "Show combined allocation statistics only" },
	{ "wa-missing-free", 'W', NULL, 0, "Workaround to alleviate misjudgments when free is missing" },
	{ "sample-rate", 's', "RATE", 0, "Sample every N-th allocation to decrease the overhead" },
	{ "top", 'T', NULL, 0, "Display only this many top allocating stacks (by size)" },
	{ "min-size", 'z', NULL, 0, "Capture only allocations larger than this size" },
	{ "max-size", 'Z', NULL, 0, "Capture only allocations smaller than this size" },
	{ "obj", 'O', "OBJ", 0, "Attach to allocator functions in the specified object" },
	{ "percpu", 'P', NULL, 0, "trace percpu allocations" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid, num;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid pid: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		env.trace_all = true;
		break;
	case 'a':
		env.show_allocs = true;
		break;
	case 'c':
		env.command = strdup(arg);
		break;
	case 'o':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			fprintf(stderr, "Invalid time: %s\n", arg);
			argp_usage(state);
		}
		env.min_age_ns = num * 1e6;
		break;
	case 'C':
		env.combined_only = true;
		break;
	case 'W':
		env.wa_missing_free = true;
		break;
	case 's':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			fprintf(stderr, "Invalid sample rate: %s\n", arg);
			argp_usage(state);
		}
		env.sample_rate = num;
		break;
	case 'z':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			fprintf(stderr, "Invalid min size: %s\n", arg);
			argp_usage(state);
		}
		env.min_size = num;
		break;
	case 'Z':
		errno = 0;
		num = strtol(arg, NULL, 10);
		if (errno || num <= 0) {
			fprintf(stderr, "Invalid max size: %s\n", arg);
			argp_usage(state);
		}
		env.max_size = num;
		break;
	case 'P':
		env.percpu = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++ > 2) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		if (pos_args == 1) {
			num = strtoll(arg, NULL, 10);
			if (errno || num <= 0) {
				fprintf(stderr, "Invalid report interval: %s\n", arg);
				argp_usage(state);
			}
			env.interval = num;
		}
		if (pos_args == 2) {
			num = strtoll(arg, NULL, 10);
			if (errno || num <= 0) {
				fprintf(stderr, "Invalid number of times to print report: %s\n", arg);
				argp_usage(state);
			}
			env.count = num;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int get_libc_path(char *path)
{
	FILE *f;
	char buf[PATH_MAX] = {};
	char *filename;
	float version;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf)
			continue;
		filename = strrchr(buf, '/') + 1;
		if (sscanf(filename, "libc-%f.so", &version) == 1) {
			memcpy(path, buf, strlen(buf));
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

struct alloc_stack {
	uint64_t stack_id;
	int size;
	int nr;
};

static int alloc_stack_cmp(const void *p1, const void *p2)
{
	const struct alloc_stack *s1 = p1, *s2 = p2;
	return s1->size < s2->size;
}

static void print_combined_outstanding_allocations(struct ksyms *ksyms, struct syms_cache *syms_cache,
		struct memleak_bpf *obj)
{
	uint64_t stack_id = 0, next_stack_id;
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	int err, i, ifd, sfd, cnt;
	unsigned long *ip;
	time_t now;
	struct tm * timeinfo;
	struct combined_alloc_info_t info;
	struct alloc_stack *stacks;
	int max_prints = env.top;

	time (&now);
	timeinfo = localtime(&now);
	printf("[%02x:%02d:%02d] Top %d stacks with outstanding allocations:\n",
		timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, env.top);

	ip = calloc(env.max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloccate memory of stack trace\n");
		return;
	}

	stacks = calloc(MAX_HASH_ENTRY_NUM, sizeof(*stacks));
	if (stacks == NULL) {
		fprintf(stderr, "failed to allocate memory for stack info\n");
		goto cleanup;
	}
	memset(stacks, 0, MAX_HASH_ENTRY_NUM * sizeof(*stacks));

	cnt = 0;
	ifd = bpf_map__fd(obj->maps.combined_allocs);
	sfd = bpf_map__fd(obj->maps.stack_traces);
	while (!bpf_map_get_next_key(ifd, &stack_id, &next_stack_id)) {
		err = bpf_map_lookup_elem(ifd, &next_stack_id, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			goto cleanup;
		}
		stack_id = next_stack_id;

		stacks[cnt].stack_id = next_stack_id;
		stacks[cnt].size = info.total_size;
		stacks[cnt].nr = info.number_of_allocs;
		cnt++;
	}

	qsort(stacks, cnt, sizeof(*stacks), alloc_stack_cmp);
	if (cnt < max_prints)
		max_prints = cnt;

	for (i = 0; i < max_prints; i++) {
		if (stacks[i].stack_id == 0) break;

		if (bpf_map_lookup_elem(sfd, &stacks[i].stack_id, ip) != 0) {
			fprintf(stderr, "    [Missed User Stack]\n");
			continue;
		}

		if (env.kernel_trace) {
			printf("\t%u bytes in %u allocations from stack\n", stacks[i].size, stacks[i].nr);
			for (int j = 0; j < env.max_stack_depth && ip[j]; j++) {
				ksym = ksyms__map_addr(ksyms, ip[j]);
				if (ksym)
					printf("\t\t%s (0x%lx)\n", ksym->name, ksym->addr);
				else
					printf("\t\t[unknown]\n");
			}

		} else {
			syms = syms_cache__get_syms(syms_cache, env.pid);
			if (!syms) {
				fprintf(stderr, "failed to get syms\n");
				continue;
			}

			printf("\t%u bytes in %u allocations from stack\n", stacks[i].size, stacks[i].nr);
			for (int j = 0; j < env.max_stack_depth && ip[j]; j++) {
				sym = syms__map_addr(syms, ip[j]);
				if (sym)
					printf("\t\t%s (0x%lx)\n", sym->name, sym->start);
				else
					printf("\t\t[unknown]\n");
			}
		}
	}

cleanup:
	if (ip) free(ip);
	if (stacks) free(stacks);

}

static void print_outstanding_allocations(struct ksyms *ksyms, struct syms_cache *syms_cache,
		struct memleak_bpf *obj)
{
	uint64_t addr = 0, next_addr;
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	int err, i, ifd, sfd, cnt;
	unsigned long *ip;
	time_t now;
	struct tm * timeinfo;
	struct alloc_info_t info;
	struct alloc_stack *stack;
	struct alloc_stack *stacks;
	int max_prints = env.top;

	struct timespec monotime;
	clock_gettime(CLOCK_MONOTONIC, &monotime);
	uint64_t now_ns = monotime.tv_sec * 1e9 + monotime.tv_nsec;

	time (&now);
	timeinfo = localtime(&now);
	printf("[%02x:%02d:%02d] Top %d stacks with outstanding allocations:\n",
		timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, env.top);

	ip = calloc(env.max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloccate memory of stack trace\n");
		return;
	}

	stacks = calloc(MAX_HASH_ENTRY_NUM, sizeof(*stacks));
	if (stacks == NULL) {
		fprintf(stderr, "failed to allocate memory for stack info\n");
		goto cleanup;
	}
	memset(stacks, 0, MAX_HASH_ENTRY_NUM * sizeof(*stacks));

	cnt = 0;
	ifd = bpf_map__fd(obj->maps.allocs);
	sfd = bpf_map__fd(obj->maps.stack_traces);
	while (!bpf_map_get_next_key(ifd, &addr, &next_addr)) {
		err = bpf_map_lookup_elem(ifd, &next_addr, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup info: %d\n", err);
			goto cleanup;
		}
		addr = next_addr;
		if (now_ns - env.min_age_ns < info.timestamp_ns)
			continue;

		stack = NULL;
		for (i = 0; i < MAX_HASH_ENTRY_NUM; i++) {
			if (stacks[i].stack_id == info.stack_id) {
				stack = &stacks[i];
				break;
			}
			if (stacks[i].stack_id == 0) {
				stack = &stacks[i];
				stack->stack_id = info.stack_id;
				cnt++;
				break;
			}
		}
		if (stack == NULL) continue;
		stack->size += info.size;
		stack->nr++;
		if (env.show_allocs)
			printf("\taddr = %lx size = %lld\n", addr, info.size);
	}

	qsort(stacks, cnt, sizeof(*stacks), alloc_stack_cmp);
	if (cnt < max_prints)
		max_prints = cnt;

	for (i = 0; i < max_prints; i++) {
		if (stacks[i].stack_id == 0) break;

		if (bpf_map_lookup_elem(sfd, &stacks[i].stack_id, ip) != 0) {
			fprintf(stderr, "    [Missed User Stack]\n");
			continue;
		}

		if (env.kernel_trace) {
			printf("\t%u bytes in %u allocations from stack\n", stacks[i].size, stacks[i].nr);
			for (int j = 0; j < env.max_stack_depth && ip[j]; j++) {
				ksym = ksyms__map_addr(ksyms, ip[j]);
				if (ksym)
					printf("\t\t%s (0x%lx)\n", ksym->name, ksym->addr);
				else
					printf("\t\t[unknown]\n");
			}

		} else {
			syms = syms_cache__get_syms(syms_cache, env.pid);
			if (!syms) {
				fprintf(stderr, "failed to get syms\n");
				continue;
			}

			printf("\t%u bytes in %u allocations from stack\n", stacks[i].size, stacks[i].nr);
			for (int j = 0; j < env.max_stack_depth && ip[j]; j++) {
				sym = syms__map_addr(syms, ip[j]);
				if (sym)
					printf("\t\t%s (0x%lx)\n", sym->name, sym->start);
				else
					printf("\t\t[unknown]\n");
			}
		}
	}

cleanup:
	if (stacks) free(stacks);
	if (ip) free(ip);
}

static void sig_handler(int signo)
{
	if (env.child_pid == 0)
		return;

	/* kill all child processes forked by command */
	if (signo == SIGINT || signo == SIGTERM)
		kill(0, SIGKILL);
}

static void exec_command(const char *cmdstr)
{
	const char *delim = " ";
	char *cmd = strdup(cmdstr);
	char **argv, *ptr, *filepath;
	int j;
	argv = malloc(sizeof(char *) * strlen(cmd));
	memset(argv, 0, sizeof(char *) * strlen(cmd));
	ptr = strtok(cmd, delim);
	if (ptr != NULL) {
		filepath = ptr;
		ptr = strtok(NULL, delim);
	} else {
		fprintf(stderr, "Failed to exec %s\n", cmdstr);
		exit(-1);
	}

	j = 0;
	while (ptr != NULL)
	{
		argv[j++] = ptr;
		ptr = strtok(NULL, delim);
	}

	env.pid = fork();
	if (env.pid == 0) {
		execve(filepath, argv, NULL);
	} else if (env.pid > 0) {
		// main process
		env.child_pid = env.pid;
		signal(SIGINT, sig_handler);
	} else {
		fprintf(stderr, "Failed to exec %s\n", env.command);
		exit(-1);
	}
}

int main(int argc, char **argv)
{
	char libc_path[PATH_MAX] = {};
	struct memleak_bpf *skel;
	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
	int err, i;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.command != NULL)
		exec_command(env.command);
	env.kernel_trace = env.pid == 0;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	skel = memleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	skel->rodata->wa_missing_free = env.wa_missing_free;
	skel->rodata->sample_rate = env.sample_rate;
	skel->rodata->min_size = env.min_size;
	skel->rodata->max_size = env.max_size;
	skel->rodata->trace_all = env.trace_all;
	if (env.kernel_trace)
		skel->rodata->stack_flags = 0;
	else
		skel->rodata->stack_flags = BPF_F_USER_STACK;

	skel->rodata->page_size = sysconf(_SC_PAGESIZE);
	bpf_map__set_value_size(skel->maps.stack_traces, 127 * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stack_traces, 10*1024);

	if (env.kernel_trace) {
		/* Disable all uprobes */
		bpf_program__set_autoload(skel->progs.uprobe_malloc, false);
		bpf_program__set_autoload(skel->progs.uprobe_realloc, false);
		bpf_program__set_autoload(skel->progs.uprobe_memalign, false);
		bpf_program__set_autoload(skel->progs.uprobe_posix_memalign, false);
		bpf_program__set_autoload(skel->progs.uprobe_valloc, false);
		bpf_program__set_autoload(skel->progs.uprobe_pvalloc, false);
		bpf_program__set_autoload(skel->progs.uprobe_aligned_alloc, false);
		if (env.percpu) {
			bpf_program__set_autoload(skel->progs.tracepoint_kmalloc, false);
			bpf_program__set_autoload(skel->progs.tracepoint_kfree, false);
			bpf_program__set_autoload(skel->progs.tracepoint_kmalloc_node, false);
			bpf_program__set_autoload(skel->progs.tracepoint_kmem_cache_alloc, false);
			bpf_program__set_autoload(skel->progs.tracepoint_kmem_cache_alloc_node, false);
			bpf_program__set_autoload(skel->progs.tracepoint_kmem_cache_free, false);
			bpf_program__set_autoload(skel->progs.tracepoint_mm_page_alloc, false);
			bpf_program__set_autoload(skel->progs.tracepoint_mm_page_free, false);
		} else {
			bpf_program__set_autoload(skel->progs.tracepoint_percpu_alloc_percpu, false);
			bpf_program__set_autoload(skel->progs.tracepoint_percpu_free_percpu, false);
		}
	} else {
		/* Disable all kernel tracepoints*/
		bpf_program__set_autoload(skel->progs.tracepoint_kmalloc, false);
		bpf_program__set_autoload(skel->progs.tracepoint_kfree, false);
		bpf_program__set_autoload(skel->progs.tracepoint_kmalloc_node, false);
		bpf_program__set_autoload(skel->progs.tracepoint_kmem_cache_alloc, false);
		bpf_program__set_autoload(skel->progs.tracepoint_kmem_cache_alloc_node, false);
		bpf_program__set_autoload(skel->progs.tracepoint_kmem_cache_free, false);
		bpf_program__set_autoload(skel->progs.tracepoint_mm_page_alloc, false);
		bpf_program__set_autoload(skel->progs.tracepoint_mm_page_free, false);
		bpf_program__set_autoload(skel->progs.tracepoint_percpu_alloc_percpu, false);
		bpf_program__set_autoload(skel->progs.tracepoint_percpu_free_percpu, false);
   }
	/* Load & verify BPF programs */
	err = memleak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* load kernel symbols */
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

	/* Attach tracepoints */
	err = memleak_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	if (env.kernel_trace) {
		printf("Attaching to kernel allocators, Ctrl+C to quit.\n");
	} else {
		/* find location of libc */
		if (env.obj != NULL) {
			if (strlen(env.obj) > PATH_MAX) {
				fprintf(stderr, "object path too long\n");
				return -1;
			}
			memcpy(libc_path, env.obj, strlen(env.obj));
		} else {
			err = get_libc_path(libc_path);
			if (err) {
				fprintf(stderr, "could not find libc.so\n");
				return -1;
			}
		}

		printf("Attaching to pid %ld, Ctrl+C to quit.\n", env.pid);
		INIT_UPROBE_URETPROBE(malloc, env.pid, libc_path, "malloc");
		INIT_UPROBE_URETPROBE(calloc, env.pid, libc_path, "calloc");
		INIT_UPROBE_URETPROBE(realloc, env.pid, libc_path, "realloc");
		INIT_UPROBE_URETPROBE(memalign, env.pid, libc_path, "memalign");
		INIT_UPROBE_URETPROBE(posix_memalign, env.pid, libc_path, "posix_memalign");
		INIT_UPROBE_URETPROBE(valloc, env.pid, libc_path, "valloc");
		INIT_UPROBE_URETPROBE(pvalloc, env.pid, libc_path, "pvalloc");
		INIT_UPROBE_URETPROBE(aligned_alloc, env.pid, libc_path, "aligned_alloc");
		INIT_UPROBE(free, env.pid, libc_path, "free");
	}

	for (i = 0; ; i++) {
		if (env.count != 0 && i >= env.count)
			 break;
		sleep(env.interval);
		if (env.combined_only)
			print_combined_outstanding_allocations(ksyms, syms_cache, skel);
		else
	   	print_outstanding_allocations(ksyms, syms_cache, skel);
	}

cleanup:
	if (syms_cache) syms_cache__free(syms_cache);
	if (ksyms) ksyms__free(ksyms);
	memleak_bpf__destroy(skel);
	return -err;
}
