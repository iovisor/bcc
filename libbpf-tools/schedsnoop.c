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
#include <stdlib.h>
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
#define PERF_BUFFER_PAGES	256

const char *argp_program_version = "schedsnoop 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
static const char argp_program_doc[] =
"Trace the related schedule events of a specified task.\n"
"\n"
"USAGE: schedsnoop -t TID [-s] [-d] [-l]\n"
"\n"
"EXAMPLES:\n"
"    schedsnoop -t 49870       	# trace tid 49870\n"
"    schedsnoop -t 49870 -s    	# trace tid 49870 and system call\n"
"    schedsnoop -t 49870 -l	# output schedule events to console\n"
"    schedsnoop -t 49870 -l -d	# output raw timestamp instead of local time\n";

static const struct argp_option opts[] = {
	{ "tid", 't', "TID", 0, "Thread ID to trace"},
	{ "syscall", 's', NULL, 0, "Trace SYSCALL info"},
	{ "debug", 'd', NULL, 0, "Debug: output raw timestamp"},
	{ "log", 'l', NULL, 0, "Output all related events"},
	{},
};

static struct env {
	int targ_tid;
	bool trace_syscall;
	bool output_log;
	bool debug;
} env = {
	.trace_syscall = false,
	.output_log = false,
	.debug = false,
};

bool volatile exiting = false;
struct timespec start_ts;
struct tm *start_tm;
int trace_stat_maps_fd;
int syscall_stat_maps_fd;

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
		break;
	case 'l':
		env.output_log = true;
		break;
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
	__u64 real_ns, tmp = ns % NS_IN_SEC;
	__u64 real_s = ns / NS_IN_SEC - start_ts.tv_sec;
	if(tmp > start_ts.tv_nsec){
		real_ns = tmp - start_ts.tv_nsec;
	} else {
		real_ns = NS_IN_SEC + tmp - start_ts.tv_nsec;
		real_s -= 1;
	}

	struct tm real_tm = {
		.tm_sec = start_tm->tm_sec,
		.tm_min = start_tm->tm_min,
		.tm_hour = start_tm->tm_hour,
	};

	real_tm.tm_sec += real_s % 60;
	real_tm.tm_min += (real_s / 60) % 60;
	real_tm.tm_hour += real_s / 3600;

	if (real_tm.tm_sec >= 60) {
		real_tm.tm_sec -= 60;
		real_tm.tm_min += 1;
	}
	if (real_tm.tm_min >= 60) {
		real_tm.tm_min -= 60;
		real_tm.tm_hour += 1;
	}
	while (real_tm.tm_hour >= 24)
		real_tm.tm_hour -= 24;	

	char date[10];
	strftime(date, sizeof(date), "%H:%M:%S", &real_tm);
		
	snprintf(buf, len, "%s.%06llu", date, real_ns / 1000);

	return 0;
}

int comp(const void *a, const void *b)
{
	return ((struct stat_info_node *)a)->avg < ((struct stat_info_node *)b)->avg;
}

static inline void pr_stat_info(int map_fd, int num, int type)
{
	struct ti_key key, prev_key;
	struct stat_info stat;
	struct stat_info_node stat_list[num];
	char comm_buf[2 * TASK_COMM_LEN];
	char avg_buf[16],long_buf[16];
	int err, idx = 0;
	
	switch (type) {
	case PREEMPTION:
		printf("\nPreemption Report:\n");
		break;
	case SYSCALL:
		printf("\nSYSCALL Report:\n");
		break;
	default:
		break;
	}
	
	while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
		err = bpf_map_lookup_elem(map_fd, &key, &stat);
		if (err < 0) {
			fprintf(stderr, "Get stat info err %d\n", err);
			break;
		}

		struct stat_info_node tmp =  {
			.cpu = key.cpu,
			.tid = key.tid,
			.count = stat.count,
			.avg = stat.total / stat.count,
			.longest = stat.longest,
		};
		
		if (key.syscall > -1) {	
			syscall_name(key.syscall, comm_buf, sizeof(comm_buf));
			snprintf(tmp.comm, sizeof(tmp.comm),
				       	"%s[%d:%s]", key.comm,
					key.syscall, comm_buf);
		} else {
			snprintf(tmp.comm, sizeof(tmp.comm),
					"%s", key.comm);
		}

		stat_list[idx++] = tmp;
		prev_key = key;
	}

	qsort(stat_list, num, sizeof(struct stat_info_node), comp);

	printf("%-5s%-7s%-30s%-7s%-10s%-10s\n", "CPU", "TID",
		       	type == PREEMPTION ? "COMM" : "SYSCALL",
		       	"Count", "Avg", "Longest");
	for (int i=0;i<(num>10?10:num);i++) {
		time_to_str(stat_list[i].avg, avg_buf, sizeof(avg_buf));
		time_to_str(stat_list[i].longest, long_buf, sizeof(long_buf));
		printf("%-5d%-7d%-30s%-7d%-10s%-10s\n",
				stat_list[i].cpu, stat_list[i].tid,
			    	stat_list[i].comm, stat_list[i].count,
				avg_buf, long_buf);
	}
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
		printf("%-20sCPU=%-7dTID=%-7dCOMM=%-20s%-37s%-17s\n",
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
	static __u64 w_start, last_time;

	time_to_str(ti->ts - last_time, d_str, sizeof(d_str));

	switch (ti->type) {
	case TYPE_MIGRATE:
		w_start = ti->ts;
		pr_ti(ti, "MIGRATE", NULL);
		break;
	case TYPE_ENQUEUE:
		w_start = ti->ts;
		printf("----------------------------\n");
		pr_ti(ti, "ENQUEUE", NULL);
		break;
	case TYPE_WAIT:
		if (ti->tid == env.targ_tid) {
			w_start = ti->ts;
			pr_ti(ti, "WAIT AFTER EXECUTED", d_str);
		} else {
			time_to_str(ti->duration,
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
			pr_ti(ti, "PREEMPT", NULL);
		}
		break;
	case TYPE_DEQUEUE:
		if (ti->tid == env.targ_tid)
			pr_ti(ti, "DEQUEUE AFTER EXECUTED", d_str);
		else {
			time_to_str(ti->duration,
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
	obj->rodata->output_log = env.output_log;
	obj->rodata->cur_tid = (int)getpid();
	
	/* Load bpf program */
	err = schedsnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
	
	/* Attach bpf program */
	if (!env.debug) {
		time_t raw_time;
		time(&raw_time);
		clock_gettime(CLOCK_MONOTONIC, &start_ts);
		start_tm = localtime(&raw_time);
	}
	err = schedsnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	
	trace_stat_maps_fd = bpf_map__fd(obj->maps.trace_stat_maps);
	syscall_stat_maps_fd = bpf_map__fd(obj->maps.syscall_stat_maps);
	
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	printf("Start tracing schedule events related to tid %d", env.targ_tid);
	if (env.trace_syscall)
		printf("(include SYSCALL)");
	printf("\nPress CTRL+C or wait until target exits to see report\n");
	
	/* setup event callbacks */
	if (env.output_log) {
		pb_opts.sample_cb = handle_event;
		pb_opts.lost_cb = handle_lost_events;
		pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
		err = libbpf_get_error(pb);
		if (err) {
			pb = NULL;
			fprintf(stderr, "Failed to open perf buffer: %d\n", err);
			goto cleanup;
		}
	}
	
	/* main: poll */
	while (!exiting && !obj->bss->targ_exit) {
	       if (env.output_log) {
			err = perf_buffer__poll(pb, 10000);
			if (err < 0)
				break;
	       } else {
		       sleep(1);
	       }
	}
	
	if (exiting)
		goto printinfo;
	if (obj->bss->targ_exit) {
		printf("Target %d Exited!\n", env.targ_tid);
		goto printinfo;
	}
	printf("Error polling perf buffer: %d\n", err);

printinfo:
	pr_stat_info(trace_stat_maps_fd, obj->bss->stat_count, PREEMPTION);
	if (env.trace_syscall)
		pr_stat_info(syscall_stat_maps_fd, obj->bss->sys_count, SYSCALL);
cleanup:
	perf_buffer__free(pb);
	schedsnoop_bpf__destroy(obj);
freename:
	free_syscall_names();
	return err != 0;
}
