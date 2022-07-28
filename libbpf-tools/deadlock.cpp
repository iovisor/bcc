/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Copyright (c) 2022 LG Electronics
 *
 * Based on deadlock(8) from BCC by Kenny Yu.
 * 01-Jul-2022   Eunseon Lee   Created this.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <map>
#include <set>
#include "deadlock.h"
#include "deadlock.skel.h"
#include "digraph/dglib/digraph.hh"
#include "digraph/dglib/digraphop.hh"
extern "C" {
#include "trace_helpers.h"
#include "uprobe_helpers.h"
}

#define warn(...)			fprintf(stderr, __VA_ARGS__)
#define MUTEX_ALIAS_LEN			128
#define MAX_LINKS			50

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_BINARY			3 /* --binary */
#define OPT_LOCK_SYMBOLS		4 /* --lock-symbols */
#define OPT_UNLOCK_SYMBOLS		5 /* --unlock-symbols */

static volatile sig_atomic_t exiting = 0;
static const char *libpthread_path = NULL;

static struct env {
	pid_t pid;
	bool verbose;
	int stack_storage_size;
	int perf_max_stack_depth;
	int edges;
	int threads;
	int interval;
	char* binary;
	char* lock_symbols;
	char* unlock_symbols;
} env = {
	.pid = -1,
	.verbose = false,
	.stack_storage_size = 655360,
	.perf_max_stack_depth = 127,
	.edges = 65536,
	.threads = 65536,
	.interval = 3,
	.binary = NULL,
	.lock_symbols = (char*)"pthread_mutex_lock",
	.unlock_symbols = (char*)"pthread_mutex_unlock",
};

const char *argp_program_version = "deadlock 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"    Detect potential deadlocks (lock inversions) in a running binary.\n"
"    Must be run as root."
"\n"
"USAGE: deadlock [OPTIONS...] [pid]\n"
"EXAMPLES:\n"
"    deadlock 181                 # Analyze PID 181\n\n"
"    deadlock 181 --binary /lib/x86_64-linux-gnu/libpthread.so.0\n"
"                                 # Analyze PID 181 and locks from this binary.\n"
"                                 # If tracing a process that is running from\n"
"                                 # a dynamically-linked binary, this argument\n"
"                                 # is required and should be the path to the\n"
"                                 # pthread library.\n\n"
"    deadlock 181 --verbose       # Analyze PID 181 and print statistics about\n"
"                                 # the mutex wait graph.\n\n"
"    deadlock 181 --lock-symbols my_mutex_lock1,my_mutex_lock2 \\\n"
"        --unlock-symbols my_mutex_unlock1,my_mutex_unlock2\n"
"                                 # Analyze PID 181 and trace custom mutex\n"
"                                 # symbols instead of pthread mutexes.\n\n";

static const struct argp_option opts[] = {
	{ "threads", 't', "MAX-THREADS", 0,
	  "the number of threads to trace (default 65536, 40 bytes per thread)"},
	{ "edges", 'e', "MAX-EDGES", 0, "the number of edge cases that can be recorded "
	  "(default 65536, 88 bytes per edge case)"},
	{ "binary", OPT_BINARY, "BINARY", 0,
	  "trace the mutexes from the binary at this path."
	  "For statically-linked binaries, this argument is not required."
	  "For dynamically-linked binaries, this argument is required and"
	  "should be the path of the pthread library the binary is using."
	  "Example: /lib/x86_64-linux-gnu/libpthread.so.0"},
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)"},
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 655360)"},
	{ "lock-symbols", OPT_LOCK_SYMBOLS, "LOCK_SYMBOLS", 0,
	  "Comma-separated list of lock symbols to trace (default \"pthread_mutex_lock\")"
	  "These symbols cannot be inlined in the binary."},
	{ "unlock-symbols", OPT_UNLOCK_SYMBOLS, "UNLOCK_SYMBOLS", 0,
	  "Comma-separated list of unlock symbols to trace (default \"pthread_mutex_unlock\")"
	  "These symbols cannot be inlined in the binary."},
	{ "interval", 'i', "INTERVAL", 0, "interval in seconds to detect potential deadlocks"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case OPT_BINARY:
		libpthread_path = strdup(arg);
		if (access(libpthread_path, F_OK)) {
			warn("Invalid libpthread: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		errno = 0;
		env.threads = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid THREADS: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		errno = 0;
		env.edges = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid EDGES: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'i':
		errno = 0;
		env.interval = strtol(arg, NULL, 10);
		if (errno || env.interval <= 0) {
			fprintf(stderr, "Invalid INTERVAL: %s\n", arg);
			argp_usage(state);
		}
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
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_LOCK_SYMBOLS:
		env.lock_symbols = strdup(arg);
		if (env.lock_symbols == NULL)
			return ARGP_ERR_UNKNOWN;
		break;
	case OPT_UNLOCK_SYMBOLS:
		env.unlock_symbols = strdup(arg);
		if (env.unlock_symbols == NULL)
			return ARGP_ERR_UNKNOWN;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (errno || env.pid <= 0) {
			fprintf(stderr, "invalid PID: %s\n", arg);
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

static int get_edge_key(__u64 m, __u64 n)
{
	__u64 data[2] = {m, n};

	return gnu_debuglink_crc32(0, (char*)data, 16); /* 16 chars from 2 64bits */
}

template <typename N, typename A>
static bool read_edges_map(int fd, digraph<N, A>& g,
			   std::map<A, struct edges_leaf_t>& edge_map)
{
	struct edges_key_t lookup_key = {}, next_key;
	struct edges_leaf_t val;
	int edge_key;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {

		err = bpf_map_lookup_elem(fd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counts: %d\n", err);
			return false;
		}

		if (env.verbose) {
			printf("[0x%016llx -> 0x%016llx] sid1: 0x%llx, sid2: 0x%llx, tid: %d, name:%s\n",
						 next_key.mutex1, next_key.mutex2,
						 val.mutex1_stack_id, val.mutex2_stack_id,
						 val.thread_pid, val.comm);
		}

		edge_key = get_edge_key(next_key.mutex1, next_key.mutex2);

		/* add edge to graph */
		g.add((const __u64)next_key.mutex1, (const __u64)next_key.mutex2, edge_key);

		/* store edge information */
		auto ret = edge_map.find(edge_key);
		if (ret == edge_map.end()) {
			edge_map.insert(std::make_pair(edge_key, val));
		} else {
			warn("duplicated edge key: %d [0x%016llx -> 0x%016llx],\
			       stack trace may be incorrect.\n", edge_key,
			       next_key.mutex1, next_key.mutex2);
		}

		lookup_key = next_key;
	}

	return true;
}

static bool read_threads_map(int fd,
			     std::map<__u32, struct thread_created_leaf_t>& parent_map)
{
	__u32 lookup_key = -1, next_key;
	struct thread_created_leaf_t val;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {

		err = bpf_map_lookup_elem(fd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counts: %d\n", err);
			return false;
		}

		/* store parent information */
		parent_map.insert(std::make_pair(next_key, val));

		lookup_key = next_key;
	}

	return true;
}

static void print_stack_trace(int sfd, const struct syms *syms, __u64 stack_id)
{
	unsigned long *ip;
	const struct sym *sym;
	int i;
	int err;

	ip = (unsigned long *)calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc user ip\n");
		return;
	}

	if (stack_id >= 0 && (err = bpf_map_lookup_elem(sfd, &stack_id, ip)) == 0) {
		if (!syms)
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++)
				printf("    0x%016lx [unknown]\n", ip[i]);
		else {
			for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
				sym = syms__map_addr(syms, ip[i]);
				printf("    0x%016lx %s\n", ip[i], sym ? sym->name : "[unknown]");
			}
		}
	} else {
		fprintf(stderr, "failed to read stack trace (stack id: %llu): %s\n",
			stack_id, strerror(errno));
	}

	free(ip);
}

/*
 * Prints the cycle in the mutex graph in the following format:
 *
 * Potential Deadlock Detected!
 *
 * Cycle in lock order graph: M0 => M1 => M2 => M0
 *
 * for (m, n) in cycle:
 * Mutex n acquired here while holding Mutex m in thread T:
 *     [ stack trace ]
 *
 * Mutex m previously acquired by thread T here:
 *     [ stack trace ]
 *
 * for T in all threads:
 * Thread T was created here:
 *     [ stack trace ]
 */
template <typename N, typename A>
static void print_cycle(int sfd, const struct syms *syms, const std::vector<N>& cycle,
			std::map<A, struct edges_leaf_t>& m_edge,
			std::map<__u32, struct thread_created_leaf_t>& m_parent)
{
	int edge_key;
	size_t i = 0;
	struct edges_leaf_t *attr;
	std::map<int, std::string> node_name; /* Map mutex address -> readable alias */
	std::set<__u32> thread_set; /* Set of threads involved in the lock inversion */
	char buf[MUTEX_ALIAS_LEN];

	printf("----------------\nPotential Deadlock Detected!\n\n");

	/* List of mutexes in the cycle, first and last repeated */
	printf("Cycle in lock order graph: ");
	for (const __u64& m : cycle) {
		/* TODO: For global or static variables, try to symbolize the mutex address. */
		snprintf(buf, MUTEX_ALIAS_LEN, "Mutex M%zu (0x%016llx)", i++, m);
		printf("%s => ", buf);
		node_name[m] = buf;
	}
	printf("%s\n\n", node_name[*cycle.begin()].c_str());

	/* For each edge in the cycle, print where the two mutexes were held */
	for (i = 0; i < cycle.size(); i++) {
		__u64 m = cycle[i];
		__u64 n = cycle[(i+1) % cycle.size()];
		edge_key = get_edge_key(m, n);

		if (env.verbose)
			printf("get edge map, mutex1: 0x%016llx, mutex2: 0x%016llx\n", m, n);

		auto ret = m_edge.find(edge_key);
		if (ret == m_edge.end()) {
			warn("failed to find edge map, mutex1: 0x%016llx, mutex2: 0x%016llx\n", m, n);
			continue;
		}

		attr = &(ret->second);

		thread_set.insert(attr->thread_pid);

		printf("%s acquired here while holding %s in Thread %d (%s):\n",
		       node_name[n].c_str(), node_name[m].c_str(), attr->thread_pid, attr->comm);
		print_stack_trace(sfd, syms, attr->mutex2_stack_id);
		printf("\n");

		printf("%s previously acquired by the same Thread %d (%s) here:\n",
		       node_name[m].c_str(), attr->thread_pid, attr->comm);
		print_stack_trace(sfd, syms, attr->mutex1_stack_id);
		printf("\n");
	}

	/* Print where the threads were created, if available */
	for (auto& tid : thread_set) {
		auto c = m_parent.find(tid);
		struct thread_created_leaf_t *p = &(c->second);

		if (p->parent_pid) {
			printf("Thread %d created by Thread %d (%s) here:\n", tid, p->parent_pid, p->comm);
			print_stack_trace(sfd, syms, p->stack_id);
		} else {
			printf("Could not find stack trace where Thread %d was created\n", tid);
		}
		printf("\n");
	}
}

/*
 * Returns the cycle from a strongly connected component(SCC)
 */
template <typename N, typename A>
static std::vector<N> cycle(const digraph<N, A> &scc)
{
	std::vector<N> cycle;
	__u64 n = *scc.nodes().begin();

	while (true) {
		cycle.push_back(n);
		for (const auto& c : scc.connections(n)) {
			if (c.first == *scc.nodes().begin()) {
				return cycle;
			}
		}
		n = (*scc.connections(n).begin()).first;
	}
}

static bool print_map(const struct syms *syms, struct deadlock_bpf *obj)
{
	int efd, tfd, sfd;
	int nr_mutex = 0;
	int nr_edge = 0;
	digraph<__u64, int> g;
	std::map<int, struct edges_leaf_t> edge_map;
	std::map<__u32, struct thread_created_leaf_t> parent_map;

	tfd = bpf_map__fd(obj->maps.thread_to_parent);
	efd = bpf_map__fd(obj->maps.edges);
	sfd = bpf_map__fd(obj->maps.stack_traces);

	/* Map of child thread pid -> parent info */
	if (!read_threads_map(tfd, parent_map)) {
		return false;
	}

	/* Mutex wait directed graph. Nodes are mutexes. Edge (A,B) exists
	 * if there exists some thread T where lock(A) was called and
	 * lock(B) was called before unlock(A) was called.
	 */
	if (!read_edges_map(efd, g, edge_map)) {
		return false;
	}

	nr_mutex = g.nodes().size();
	if (nr_mutex <= 0)
		return false;

	nr_edge = edge_map.size();

	if (env.verbose) {
		printf("Mutexes: %d, Edges: %d\n", nr_mutex, nr_edge);
		for (const auto& c: parent_map) {
			printf("[%d's parent] pid: %d, stack_id: 0x%llx, name: %s\n",
			       c.first, c.second.parent_pid, c.second.stack_id, c.second.comm);
		}
	}

	if (cycles(g) > 0) {
		auto h  = graph2dag(g);
		auto s  = serialize(h);

		for (const auto &scc : s) {
			/* skip single node SCC */
			if (scc.nodes().size() > 1) {
				/* get a cycle from SCC */
				const auto& c = cycle(scc);
				print_cycle(sfd, syms, c, edge_map, parent_map);
			}
		}
		return true;
	}

	return false;
}

static int get_libpthread_path(char *path)
{
	FILE *f;
	char buf[PATH_MAX] = {};
	char *filename;
	float version;

	if (libpthread_path) {
		memcpy(path, libpthread_path, strlen(libpthread_path));
		return 0;
	}

	snprintf(buf, PATH_MAX, "/proc/%d/maps", env.pid);
	f = fopen(buf, "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf)
			continue;
		filename = strrchr(buf, '/') + 1;
		if (sscanf(filename, "libpthread-%f.so", &version) == 1) {
			memcpy(path, buf, strlen(buf));
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

static int attach_uprobes(struct deadlock_bpf *obj, struct bpf_link *links[])
{
	char libpthread_path[PATH_MAX] = {};
	off_t func_off;
	char *symbol;
	int idx = 0;
	int err;

	obj->links.dummy_clone = bpf_program__attach(obj->progs.dummy_clone);
	if (!obj->links.dummy_clone) {
		err = -errno;
		warn("failed to attach kprobe clone: %d\n", err);
		return -1;
	}

	err = get_libpthread_path(libpthread_path);
	if (err) {
		warn("could not find libpthread.so\n");
		return -1;
	}

	symbol = strtok(env.unlock_symbols, ",");
	while (symbol) {
		if (idx >= MAX_LINKS) {
			fprintf(stderr, "the number of probe is too big, please "
				"increase MAX_LINKS's value and recompile");
			return -1;
		}

		func_off = get_elf_func_offset(libpthread_path, symbol);
		if (func_off < 0) {
			warn("could not find %s in %s\n", symbol, libpthread_path);
			return -1;
		}
		links[idx] = bpf_program__attach_uprobe(obj->progs.dummy_mutex_unlock, false,
						      env.pid ?: -1, libpthread_path, func_off);
		if (!links[idx]) {
			warn("failed to attach %s: %d\n", symbol, -errno);
			return -1;
		}

		idx++;
		symbol = strtok(NULL, ",");
	}

	symbol = strtok(env.lock_symbols, ",");
	while (symbol) {
		if (idx >= MAX_LINKS) {
			fprintf(stderr, "the number of probe is too big, please "
				"increase MAX_LINKS's value and recompile");
			return -1;
		}

		func_off = get_elf_func_offset(libpthread_path, symbol);
		if (func_off < 0) {
			warn("could not find %s in %s\n", symbol, libpthread_path);
			return -1;
		}
		links[idx] = bpf_program__attach_uprobe(obj->progs.dummy_mutex_lock, false,
						      env.pid ?: -1, libpthread_path, func_off);
		if (!links[idx]) {
			warn("failed to attach %s: %d\n", symbol, -errno);
			return -1;
		}
		idx++;
		symbol = strtok(NULL, ",");
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = NULL,
		.doc = argp_program_doc,
	};
	struct syms_cache *syms_cache = NULL;
	const struct syms *syms = NULL;
	struct bpf_link *links[MAX_LINKS] = {};
	struct deadlock_bpf *obj;
	int err, i;
	bool cycle = false;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = deadlock_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_pid = env.pid;

	bpf_map__set_value_size(obj->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));

	bpf_map__set_max_entries(obj->maps.stack_traces, env.stack_storage_size);
	bpf_map__set_max_entries(obj->maps.thread_to_held_mutexes, env.threads);
	bpf_map__set_max_entries(obj->maps.edges, env.edges);

	err = deadlock_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}

	err = attach_uprobes(obj, links);
	if (err)
		goto cleanup;

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}
	syms = syms_cache__get_syms(syms_cache, env.pid);

	signal(SIGINT, sig_handler);

	printf("Tracing... Hit Ctrl-C to end.\n");

	while (1) {
		sleep(env.interval);

		cycle = print_map(syms, obj);

		if (exiting || cycle)
			break;
	}

cleanup:
	for (i = 0; i < MAX_LINKS; i++)
		bpf_link__destroy(links[i]);
	deadlock_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	return err != 0;
}
