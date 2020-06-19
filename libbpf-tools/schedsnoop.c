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
#include <time.h>
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
"USAGE: schedsnoop -t TID [-s] [-d]\n"
"\n"
"EXAMPLES:\n"
"    schedsnoop -t 49870       	# trace tid 49870\n"
"    schedsnoop -t 49870 -s    	# trace tid 49870 and system call\n"
"    schedsnoop -t 49870 -d	# debug mode, output raw timestamp\n";

static const struct argp_option opts[] = {
	{ "tid", 't', "TID", 0, "Thread ID to trace"},
	{ "syscall", 's', NULL, 0, "Trace SYSCALL info"},
	{ "debug", 'd', NULL, 0, "Debug: output raw timestamp"},
	{},
};

static struct env {
	int targ_tid;
	bool trace_syscall;
	bool debug;
} env = {
	.trace_syscall = false,
	.debug = false,
};

bool volatile exiting = false;
struct timespec start_ts;
struct timespec real_ts;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int tid;
	switch (key) {
	case 't':
		tid = strtol(arg, NULL, 10);
		if (tid <= 0) {
			fprintf(stderr, "Invalid thread ID: %s\n", arg);
			argp_usage(state);
		}
		env.targ_tid = tid;
		break;
	case 's':
		env.trace_syscall = true;
		break;
	case 'd':
		env.debug = true;
	case ARGP_KEY_END:
		if (!env.targ_tid) {
			fprintf(stderr, "Target thread ID is required!\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static inline int time_to_str(__u64 ns, char *buf, size_t len)
{
	if (ns >= 10 * NS_IN_SEC)
		snprintf(buf, len, "%llus", ns / NS_IN_SEC);
	else if (ns >= 10 * NS_IN_MS)
		snprintf(buf, len, "%llums", ns / NS_IN_MS);
	else if (ns >= 10 * NS_IN_US)
		snprintf(buf, len, "%lluus", ns / NS_IN_US);
	else
		snprintf(buf, len, "%lluns", ns);

	return 0;
}

static inline int time_to_real_time(__u64 ns, char *buf, size_t len)
{
	__u64 real_ns, tmp = ns % NS_IN_SEC + real_ts.tv_nsec;
	time_t real_s = ns / NS_IN_SEC + real_ts.tv_sec - start_ts.tv_sec;
	if(tmp > start_ts.tv_nsec){
		real_ns = tmp - start_ts.tv_nsec;
	} else {
		real_ns = start_ts.tv_nsec - tmp;
		real_s -= 1;
	}
	while (real_ns > NS_IN_SEC) {
		real_ns -= NS_IN_SEC;
		real_s += 1;
	}

	struct tm *real_tm = localtime(&real_s);
	char date[20];
	strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", real_tm);
		
	snprintf(buf, len, "%s.%06llu", date, real_ns / 1000);

	return 0;
}

static inline void pr_ti(struct trace_info *ti, char *opt, char *delay)
{
	char buf[32];
	if (env.debug) {
		snprintf(buf, sizeof(buf), "%llu", ti->ts);
		printf("%-20sCPU=%-7dTID=%-7dCOMM=%-20s%-37s%-17s\n",
				buf, ti->cpu, ti->tid, ti->comm, opt,
				delay ? delay : "");
	} else {
		time_to_real_time(ti->ts, buf, sizeof(buf));
		printf("%-32sCPU=%-7dTID=%-7dCOMM=%-20s%-37s%-17s\n",
				buf, ti->cpu, ti->tid, ti->comm, opt,
				delay ? delay : "");
	}
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct trace_info *ti = data;
	char d_str[16];
	char comm_buf[2 * TASK_COMM_LEN];
	char func[80];
	static __u64 w_start, p_start, last_time;

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
		if (ti->tid == env.targ_tid) {
			w_start = ti->ts;
			pr_ti(ti, "WAIT AFTER EXECUTED", d_str);
		} else {
			time_to_str(ti->ts - p_start,
					d_str, sizeof(d_str));
			pr_ti(ti, "PREEMPTED", d_str);
		}
		break;
	case TYPE_EXECUTE:
		if (ti->tid == env.targ_tid) {
			time_to_str(ti->ts - w_start,
					d_str, sizeof(d_str));
			pr_ti(ti, "EXECUTE AFTER WAITED", d_str);
		} else {
			p_start = ti->ts;
			pr_ti(ti, "PREEMPT", NULL);
		}
		break;
	case TYPE_DEQUEUE:
		if (ti->tid == env.targ_tid)
			pr_ti(ti, "DEQUEUE AFTER EXECUTED", d_str);
		else {
			time_to_str(ti->ts - p_start,
					d_str, sizeof(d_str));
			pr_ti(ti, "DEQUEUE AFTER PREEMPTED", d_str);
		}
		break;
	case TYPE_SYSCALL_ENTER:
		syscall_name(ti->syscall, comm_buf, sizeof(comm_buf));
		snprintf(func, sizeof(func), "SC [%d:%s] ENTER",
				ti->syscall, comm_buf);
		pr_ti(ti, func, NULL);
		break;
	case TYPE_SYSCALL_EXIT:
		time_to_str(ti->duration, d_str, sizeof(d_str));
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
	obj->rodata->targ_tid = env.targ_tid;
	obj->rodata->trace_syscall = env.trace_syscall;
	
	/* Load bpf program */
	err = schedsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
	
	/* Attach bpf program */
	if (!env.debug) {
		clock_gettime(CLOCK_REALTIME, &real_ts);
		clock_gettime(CLOCK_MONOTONIC, &start_ts);
	}
	err = schedsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	printf("Start tracing schedule events ");
	if (env.trace_syscall)
		printf("(include SYSCALL)");
	printf("\nTarget thread ID %d\n", env.targ_tid);
	
	/* setup event callbacks */
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}
	
	/* main: poll */
	while (!exiting && !obj->bss->targ_exit && 
			(err = perf_buffer__poll(pb, 100)) >= 0);
	if (exiting)
		goto cleanup;
	if (obj->bss->targ_exit) {
		printf("Target %d Exited!\n", env.targ_tid);
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
