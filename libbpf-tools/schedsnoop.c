// SPDX-Licence-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
//
// Based on schedsnoop by Michael Wang
// Created by Wenhao Qu
//
// Maintainers:
// Michael Wang <yun.wang@linux.alibaba.com>
// Wenhao Qu <quxi.qwh@alibaba-inc.com>
#include <argp.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <dirent.h>
#include <bpf/bpf.h>
#include "errno_helpers.h"
#include "trace_helpers.h"
#include "syscall_helpers.h"
#include "schedsnoop.h"
#include "schedsnoop.skel.h"

#define NS_IN_SEC		1000000000LLU
#define NS_IN_MS		1000000LLU
#define NS_IN_US		1000LLU
#define PERF_BUFFER_PAGES	64

const char *argp_program_version = "schedsnoop 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
static const char argp_program_doc[] =
"Trace the related schedule events of a specified task.\n"
"\n"
"USAGE: schedsnoop -p PID [-s]\n"
"\n"
"EXAMPLES:\n"
"    schedsnoop -p 49870       	# trace pid 49870\n"
"    schedsnoop -p 49870 -s    	# trace pid 49870 and system call\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace"},
	{ "syscall", 's', NULL, 0, "Trace SYSCALL Info"},
	{},
};

static struct env {
	int nr_cpus;
	int trace_syscall;
	int target;
} env;

int ti_map_fd;
int si_map_fd;
int start_map_fd;
int end_map_fd;
bool exiting = false;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int pid;
	switch (key) {
	case 'p':
		if(arg == NULL) {
			fprintf(stderr, "PID is required\n");
			argp_usage(state);
		} else {
			pid = strtol(arg, NULL, 10);
			if (pid <= 0) {
				fprintf(stderr, "Invalid PID: %s\n", arg);
				argp_usage(state);
			}
			env.target = pid;
		}
		break;
	case 's':
		env.trace_syscall = 1;
		break;
	case ARGP_KEY_END:
		if (!env.target) {
			fprintf(stderr, "No target PID\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static inline int time_to_str(u64 ns, char *buf, size_t len)
{

	if (ns > 10 * NS_IN_SEC)
		snprintf(buf, len, "%llus", ns / NS_IN_SEC);
	else if (ns > 10 * NS_IN_MS)
		snprintf(buf, len, "%llums", ns / NS_IN_MS);
	else if (ns > 10 * NS_IN_US)
		snprintf(buf, len, "%lluus", ns / NS_IN_US);
	else
		snprintf(buf, len, "%lluns", ns);

	return 0;
}

static inline void pr_ti(struct trace_info *ti, char *opt, char *delay)
{
	char buf[27];
	snprintf(buf, sizeof(buf), "%lluus", ti->ts / NS_IN_US);
	printf("%-27sCPU=%-7dPID=%-7dCOMM=%-20s%-37s%-17s\n",
				buf, ti->cpu, ti->pid, ti->comm, opt,
				delay ? delay : "");
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct trace_info *ti = data;
	char d_str[16];
	char comm_buf[2 * TASK_COMM_LEN];
	char func[80];
	struct si_key sik;
	u64 siv;
	static u64 w_start, p_start, last_time;


	time_to_str(ti->ts - last_time, d_str, sizeof(d_str));

	switch (ti->type) {
	case TYPE_MIGRATE:
		w_start = p_start = ti->ts;
		pr_ti(ti, "MIGRATE", NULL);
		break;
	case TYPE_ENQUEUE:
		w_start = p_start = ti->ts;
		printf("----------------------------\n");
		pr_ti(ti, "ENQUEUE", NULL);
		break;
	case TYPE_WAIT:
		if (ti->pid == env.target) {
			w_start = ti->ts;
			pr_ti(ti, "WAIT AFTER EXECUTED", d_str);
		} else {
			time_to_str(ti->ts - p_start,
					d_str, sizeof(d_str));
			pr_ti(ti, "PREEMPTED", d_str);
		}
		break;
	case TYPE_EXECUTE:
		if (ti->pid == env.target) {
			time_to_str(ti->ts - w_start,
					d_str, sizeof(d_str));
			pr_ti(ti, "EXECUTE AFTER WAITED", d_str);
		} else {
			p_start = ti->ts;
			pr_ti(ti, "PREEMPT", NULL);
		}
		break;
	case TYPE_DEQUEUE:
		if (ti->pid == env.target)
			pr_ti(ti, "DEQUEUE AFTER EXECUTED", d_str);
		else {
			time_to_str(ti->ts - p_start,
					d_str, sizeof(d_str));
			pr_ti(ti, "DEQUEUE AFTER PREEMPTED", d_str);
		}
		break;
	case TYPE_SYSCALL_ENTER:
		siv = ti->ts;
		sik.cpu = ti->cpu;
		sik.pid = ti->pid;
		sik.syscall = ti->syscall;
		bpf_map_update_elem(si_map_fd, &sik, &siv, BPF_ANY);
		syscall_name(ti->syscall, comm_buf, sizeof(comm_buf));
		snprintf(func, sizeof(func), "SC [%d:%s] ENTER",
				ti->syscall, comm_buf);
		pr_ti(ti, func, NULL);
		break;
	case TYPE_SYSCALL_EXIT:
		sik.cpu = ti->cpu;
		sik.pid = ti->pid;
		sik.syscall = ti->syscall;
		if (bpf_map_lookup_elem(si_map_fd, &sik, &siv))
			break;
		time_to_str(ti->ts - siv, d_str, sizeof(d_str));
		bpf_map_delete_elem(si_map_fd, &sik);
		syscall_name(ti->syscall, comm_buf, sizeof(comm_buf));
		snprintf(func, sizeof(func), "SC [%d:%s] TAKE %s TO EXIT",
				ti->syscall, comm_buf, d_str);
		pr_ti(ti, func, NULL);
		break;
	default:
		break;
	}

	last_time = ti->ts;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void int_exit(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	struct schedsnoop_bpf *obj;	
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	init_syscall_names();
	
	/* Check cpu number */
	env.nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (env.nr_cpus > NR_CPU_MAX) {
		printf("Support Maximum %d cpus\n", NR_CPU_MAX);
		goto freename;
	}
	
	/* Increase rlimit */
	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		goto freename;
	}
	
	/* Open bpf object */
	obj = schedsnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		goto freename;
	}

	/* initialize global data (filtering options) */
	obj->rodata->targ_pid = env.target;
	obj->rodata->trace_syscall = env.trace_syscall;
	
	/* Load bpf program */
	err = schedsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
	
	/* Attach bpf program */
	err = schedsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	
	/* Setup global map fd */
	si_map_fd = bpf_map__fd(obj->maps.syscall_info_maps);
	
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	printf("Start tracing schedule events ");
	if (env.trace_syscall)
		printf("(include SYSCALL)");
	printf("\nTarget task pid %d\n", env.target);
	
	/* setup event callbacks */
	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}
	
	/* main: poll */
	while (!exiting && !obj->bss->targ_exit && \
			(err = perf_buffer__poll(pb, 100)) >= 0);
	if (exiting)
		goto cleanup;
	if (obj->bss->targ_exit) {
		printf("Target %d Destroyed!\n", env.target);
		goto cleanup;
	}
	printf("Error polling perf buffer: %d\n", err);
	
cleanup:
	perf_buffer__free(pb);
	schedsnoop_bpf__destroy(obj);
freename:
	free_syscall_names();
	return err != 0;
}
