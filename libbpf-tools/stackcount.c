// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025, Ism Hong
 *
 * Based on stackcount(8) from BCC by Brendan Gregg and others.
 * 2025-10-13   Ism Hong   Created this.
 *
 * TODO:
 * - Add regex support
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <regex.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fnmatch.h>
#include <fcntl.h>
#include "stackcount.h"
#include "stackcount.skel.h"
#include "trace_helpers.h"

#ifndef USE_BLAZESYM
struct usyms;
struct usym {
	const char *name;
};
static struct usyms *usyms__new(pid_t pid, const char *path) { return NULL; }
static void usyms__free(struct usyms *usyms) {}
static const struct usym *usyms__lookup_addr(struct usyms *usyms, unsigned long long addr) { return NULL; }
#endif

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define OPT_PERF_MAX_STACK_DEPTH 1
#define OPT_STACK_STORAGE_SIZE 2

static struct env {
	pid_t pid;
	int cpu;
	long interval;
	long duration;
	bool timestamp;
	bool regexp;
	bool offset;
	bool perpid;
	bool kernel_stacks_only;
	bool user_stacks_only;
	bool verbose;
	bool delimited;
	bool folded;
	char *pattern;
	char *cgroup_path;
	bool cg;
	int stack_storage_size;
	int perf_max_stack_depth;
} env = {
	.interval = 99999999,
	.duration = 99999999,
	.cpu = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
};

static volatile bool exiting;
static struct bpf_link **links = NULL;
static int num_links = 0;

const char *argp_program_version = "stackcount 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Count events and their stack traces.\n"
"\n"
"USAGE: stackcount [-h] [-p PID] [-c CPU] [-i INTERVAL] [-D DURATION] [-T]"
"                  [-r] [-s] [-P] [-K] [-U] [-v] [-d] [-f] pattern"
"\n"
"EXAMPLES:"
"    ./stackcount submit_bio         # count kernel stack traces for submit_bio"
"    ./stackcount -d ip_output       # include a user/kernel stack delimiter"
"    ./stackcount -s ip_output       # show symbol offsets"
"    ./stackcount -sv ip_output      # show offsets and raw addresses (verbose)"
"    ./stackcount 'tcp_send*'        # count stacks for funcs matching tcp_send*"
"    ./stackcount -r '^tcp_send.*'   # same as above, using regular expressions"
"    ./stackcount -Ti 5 ip_output    # output every 5 seconds, with timestamps"
"    ./stackcount -p 185 ip_output   # count ip_output stacks for PID 185 only"
"    ./stackcount -c 1 put_prev_entity   # count put_prev_entity stacks for CPU 1 only"
"    ./stackcount -p 185 c:malloc    # count stacks for malloc in PID 185"
"    ./stackcount t:sched:sched_fork # count stacks for sched_fork tracepoint"
"    ./stackcount -p 185 u:node:*    # count stacks for all USDT probes in node"
"    ./stackcount -K t:sched:sched_switch   # kernel stacks only"
"    ./stackcount -U t:sched:sched_switch   # user stacks only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "cpu", 'c', "CPU", 0, "Trace this CPU only", 0 },
	{ "interval", 'i', "SECONDS", 0, "Summary interval, seconds", 0 },
	{ "duration", 'D', "SECONDS", 0, "Total duration of trace, seconds", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "regexp", 'r', NULL, 0, "Use regular expressions. "
		"Default is '*' wildcards only.", 0 },
	{ "offset", 's', NULL, 0, "Show address offsets", 0 },
	{ "perpid", 'P', NULL, 0, "Display stacks separately for each process", 0 },
	{ "kernel-stacks-only", 'K', NULL, 0, "kernel stack only", 0 },
	{ "user-stacks-only", 'U', NULL, 0, "user stack only", 0 },
	{ "verbose", 'v', NULL, 0, "Show raw addresses", 0 },
	{ "delimited", 'd', NULL, 0, "Insert delimiter between kernel/user stacks", 0 },
	{ "folded", 'f', NULL, 0, "Output folded format", 0 },
	{ "cgroup", 'C', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "SIZE", 0,
		"The number of unique stack traces that can be stored and displayed "
		"(default 1024)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "DEPTH", 0,
		"The limit for both kernel and user stack traces (default 127)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		break;
	case 'c':
		env.cpu = strtol(arg, NULL, 10);
		break;
	case 'i':
		env.interval = strtol(arg, NULL, 10);
		break;
	case 'D':
		env.duration = strtol(arg, NULL, 10);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'r':
		env.regexp = true;
		break;
	case 's':
		env.offset = true;
		break;
	case 'P':
		env.perpid = true;
		break;
	case 'K':
		env.kernel_stacks_only = true;
		break;
	case 'U':
		env.user_stacks_only = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.delimited = true;
		break;
	case 'f':
		env.folded = true;
		break;
	case 'C':
		env.cgroup_path = arg;
		env.cg = true;
		break;
	case OPT_STACK_STORAGE_SIZE:
		env.stack_storage_size = strtol(arg, NULL, 10);
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			warn("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.pattern = arg;
		break;
	case ARGP_KEY_END:
		if (!pos_args) {
			warn("Pattern required.\n");
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

static void sig_handler(int sig)
{
	exiting = true;
}

struct count_info {
	struct key_t key;
	__u64 value;
};

static int sort_by_value(const void *a, const void *b)
{
	const struct count_info *A = a;
	const struct count_info *B = b;

	return A->value - B->value;
}

static void print_stacks(struct stackcount_bpf *skel, struct ksyms *ksyms, struct usyms *usyms)
{
	int counts_fd = bpf_map__fd(skel->maps.counts);
	int stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);
	struct key_t *lookup_key = NULL, next_key;
	__u64 value;
	static __u64 *stack;
	size_t i;

	stack = calloc(env.perf_max_stack_depth, sizeof(__u64));
	if (!stack) {
		warn("failed to allocate stack array\n");
		return;
	}

	if (env.timestamp) {
		char ts[32];
		time_t t;

		time(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
		printf("%-8s\n", ts);
	}

	// Read map and sort
	struct count_info *items = NULL;
	size_t items_size = 0;
	size_t items_capacity = 0;

	while (bpf_map_get_next_key(counts_fd, lookup_key, &next_key) == 0) {
		if (bpf_map_lookup_elem(counts_fd, &next_key, &value) != 0) {
			warn("bpf_map_lookup_elem failed\n");
			goto cleanup;
		}

		if (items_size >= items_capacity) {
			items_capacity = items_capacity == 0 ? 64 : items_capacity * 2;
			struct count_info *new_items =
					realloc(items, items_capacity * sizeof(*items));
			if (!new_items) {
				warn("realloc failed\n");
				goto cleanup;
			}
			items = new_items;
		}
		items[items_size].key = next_key;
		items[items_size].value = value;
		items_size++;

		lookup_key = &next_key;
	}

	qsort(items, items_size, sizeof(*items), sort_by_value);

	// Print sorted stacks
	for (i = 0; i < items_size; i++) {
		if (env.folded) {
			// print folded stack output
			printf("%s;", items[i].key.name);
			if (usyms && items[i].key.user_stack_id >= 0) {
				if (bpf_map_lookup_elem(stack_traces_fd, &items[i].key.user_stack_id, stack) != 0) {
					warn("failed to lookup user stack table\n");
					continue;
				}
				for (int j = 0; j < env.perf_max_stack_depth && stack[j]; j++) {
					const struct usym *sym = usyms__lookup_addr(usyms, stack[j]);
					printf("%s;", sym ? sym->name : "[unknown]");
				}
			}
			if (env.delimited)
				printf("-;");

			if (items[i].key.kernel_stack_id >= 0) {
				if (bpf_map_lookup_elem(stack_traces_fd, &items[i].key.kernel_stack_id, stack) != 0) {
					warn("failed to lookup kernel stack table, id = %d: %s\n",
							items[i].key.kernel_stack_id, strerror(errno));
					continue;
				}
				for (int j = 0; j < env.perf_max_stack_depth && stack[j]; j++) {
					const struct ksym *sym = ksyms__map_addr(ksyms, stack[j]);
					printf("%s;", sym ? sym->name : "[unknown]");
				}
			}
			printf(" %llu\n", items[i].value);
		} else {
			// print multi-line stack output
			if (items[i].key.kernel_stack_id >= 0) {
				if (bpf_map_lookup_elem(stack_traces_fd, &items[i].key.kernel_stack_id, stack) != 0) {
					warn("failed to lookup kernel stack table\n");
					continue;
				}
				for (int j = 0; j < env.perf_max_stack_depth && stack[j]; j++) {
					const struct ksym *sym = ksyms__map_addr(ksyms, stack[j]);

					if (env.verbose) {
						if (env.offset && sym)
							printf("    %p %s+0x%llx\n",
									(void *)stack[j], sym->name,
									stack[j] - sym->addr);
						else
							printf("    %p %s\n",
									(void *)stack[j],
									sym ? sym->name : "[unknown]");
					} else {
						if (env.offset && sym)
							printf("    %s+0x%llx\n",
									sym->name,
									stack[j] - sym->addr);
						else
							printf("    %s\n",
									sym ? sym->name : "[unknown]");
					}
				}
			}

			if (env.delimited)
				printf("    --\n");

			if (usyms && items[i].key.user_stack_id >= 0) {
				if (bpf_map_lookup_elem(stack_traces_fd, &items[i].key.user_stack_id, stack) != 0) {
					warn("failed to lookup user stack table\n");
					continue;
				}
				for (int j = 0; j < env.perf_max_stack_depth && stack[j]; j++) {
					const struct usym *sym = usyms__lookup_addr(usyms, stack[j]);
					if (env.verbose)
						printf("    %p %s\n", (void *)stack[j], sym ? sym->name : "[unknown]");
					else
						printf("    %s\n", sym ? sym->name : "[unknown]");
				}
			}
			if (env.perpid)
				printf("    %s [%d]\n", items[i].key.name, items[i].key.tgid);

			printf("    %llu\n\n", items[i].value);
		}
	}

cleanup:
	free(stack);
	free(items);
	// Clear map for next interval
	lookup_key = NULL;
	while (bpf_map_get_next_key(counts_fd, lookup_key, &next_key) == 0) {
		bpf_map_delete_elem(counts_fd, &next_key);
		lookup_key = &next_key;
	}
}

static int attach_kprobes(struct stackcount_bpf *skel)
{
	char *p = strdup(env.pattern);
	int err = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return -errno;

	char line[256];
	while (fgets(line, sizeof(line), f)) {
		char type;
		char name[256];
		unsigned long long addr;

		if (sscanf(line, "%llx %c %s", &addr, &type, name) != 3)
			continue;

		if (type != 'T' && type != 't')
			continue;

		if (fnmatch(p, name, 0) == 0) {
			struct bpf_link *link = bpf_program__attach_kprobe(skel->progs.kprobe_prog, false, name);
			if (!link) {
				err = -1;
				goto out;
			}
			num_links++;
			links = realloc(links, num_links * sizeof(*links));
			links[num_links - 1] = link;
		}
	}

out:
	fclose(f);
	free(p);
	return err;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct stackcount_bpf *skel;
	struct ksyms *ksyms = NULL;
	struct usyms *usyms = NULL;
	int err;
	char *p;
	char *probe_type, *library, *probe;
	int cgroup_fd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.kernel_stacks_only && env.user_stacks_only) {
		warn("-K and -U are mutually exclusive.\n");
		return 1;
	}

#ifndef USE_BLAZESYM
	if (env.user_stacks_only || !env.kernel_stacks_only) {
		warn("user stacks not supported without blazesym, kernel stacks will be used\n");
		env.user_stacks_only = false;
		env.kernel_stacks_only = true;
	}
#endif

	libbpf_set_print(libbpf_print_fn);

	skel = stackcount_bpf__open();
	if (!skel) {
		warn("failed to open BPF object\n");
		return 1;
	}

	bpf_map__set_value_size(skel->maps.stack_traces,
						env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(skel->maps.stack_traces, env.stack_storage_size);

	skel->rodata->target_pid = env.pid;
	skel->rodata->target_cpu = env.cpu;
	skel->rodata->kernel_stacks_only = env.kernel_stacks_only;
	skel->rodata->user_stacks_only = env.user_stacks_only;
	skel->rodata->per_pid = env.perpid;

	p = strdup(env.pattern);
	probe_type = strtok(p, ":");
	if (!probe_type) {
		warn("invalid pattern: %s\n", env.pattern);
		free(p);
		return 1;
	}

	if (strcmp(probe_type, "t") == 0) {
		bpf_program__set_autoload(skel->progs.kprobe_prog, false);
		bpf_program__set_autoload(skel->progs.uprobe_prog, false);
	} else if (strcmp(probe_type, "u") == 0) {
		bpf_program__set_autoload(skel->progs.kprobe_prog, false);
		bpf_program__set_autoload(skel->progs.tp_prog, false);
	} else { // kprobe
		bpf_program__set_autoload(skel->progs.tp_prog, false);
		bpf_program__set_autoload(skel->progs.uprobe_prog, false);
	}

	if (env.cg) {
		cgroup_fd = open(env.cgroup_path, O_RDONLY);
		if (cgroup_fd < 0) {
			warn("failed to open cgroup path: %s\n", env.cgroup_path);
			goto cleanup;
		}
		bpf_program__attach_cgroup(skel->progs.kprobe_prog, cgroup_fd);
		bpf_program__attach_cgroup(skel->progs.tp_prog, cgroup_fd);
		bpf_program__attach_cgroup(skel->progs.uprobe_prog, cgroup_fd);
	}

	err = stackcount_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	// re-parse pattern for attach
	free(p);
	p = strdup(env.pattern);
	probe_type = strtok(p, ":");

	if (strcmp(probe_type, "t") == 0) {
		char *category = strtok(NULL, ":");
		char *event = strtok(NULL, ":");
		struct bpf_link *link = bpf_program__attach_tracepoint(skel->progs.tp_prog,
										category, event);
		if (!link) {
			err = -errno;
			warn("failed to attach tracepoint: %d\n", err);
			goto cleanup;
		}
		num_links++;
		links = realloc(links, num_links * sizeof(*links));
		links[num_links - 1] = link;
	} else if (strcmp(probe_type, "u") == 0) {
		library = strtok(NULL, ":");
		probe = strtok(NULL, ":");
		if (!library || !probe) {
			warn("invalid uprobe pattern\n");
			err = -1;
			goto cleanup;
		}
		struct bpf_uprobe_opts opts = { .sz = sizeof(opts),
										.func_name = probe,
										.retprobe = false };
		struct bpf_link *link = bpf_program__attach_uprobe_opts(
			skel->progs.uprobe_prog, env.pid ?: -1, library, 0, &opts);
		if (!link) {
			err = -errno;
			warn("failed to attach uprobe: %d\n", err);
			goto cleanup;
		}
		num_links++;
		links = realloc(links, num_links * sizeof(*links));
		links[num_links - 1] = link;
	} else {
		err = attach_kprobes(skel);
		if (err) {
			warn("failed to attach kprobes\n");
			goto cleanup;
		}
	}


	ksyms = ksyms__load();
	if (!ksyms) {
		warn("failed to load kallsyms\n");
		goto cleanup;
	}
	usyms = usyms__new(env.pid ?: -1, NULL);
	if (!usyms && (env.user_stacks_only || !env.kernel_stacks_only)) {
		warn("failed to load usyms\n");
		goto cleanup;
	}

	printf("Tracing... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting) {
		sleep(env.interval);
		if (env.duration-- == 0)
			break;
		print_stacks(skel, ksyms, usyms);
	}

	printf("Detaching...\n");

cleanup:
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	for (int i = 0; i < num_links; i++)
		bpf_link__destroy(links[i]);
	free(links);
	stackcount_bpf__destroy(skel);
	ksyms__free(ksyms);
	usyms__free(usyms);
	free(p);

	return err != 0;
}
