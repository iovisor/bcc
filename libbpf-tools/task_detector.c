// SPDX-Licence-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
//
// Based on task_detector by Michael Wang
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
#include "task_detector.h"
#include "task_detector.skel.h"

const char *argp_program_version = "task_detector 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
static const char argp_program_doc[] =
"Trace the related schedule events of a specified task.\n"
"\n"
"USAGE: task_detector -p PID [-s]\n"
"\n"
"EXAMPLES:\n"
"    task_detector -p 49870       	# trace pid 49870\n"
"    task_detector -p 49870 -s    	# trace pid 49870 and system call\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace"},
	{ "syscall", 's', NULL, 0, "Trace SYSCALL Info"},
	{},
};

static struct env {
	int ui_map_fd;
	int ti_map_fd;
	int si_map_fd;
	int start_map_fd;
	int end_map_fd;
	bool exiting;
	int nr_cpus;
	int trace_syscall;
	int target;
} env = {
	.exiting = false,
};

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


static inline int get_comm(int pid, char comm[])
{
	int fd, ret = 1;
	char path_buf[512];

	comm[0] = '\0';

	if (!pid) {
		strcpy(comm, "IDLE");
		return 0;
	}

	snprintf(path_buf, sizeof(path_buf), "/proc/%d/comm", pid);
	fd = open(path_buf, O_RDONLY);
	if (fd) {
		int cnt;

		cnt = read(fd, comm, 16);
		if (cnt > 0) {
			comm[cnt - 1] = '\0';
			ret = 0;
		}
	}
	close(fd);
	return ret;
}

static inline int time_to_str(u64 ns, char *buf, size_t len)
{
	u64 us = ns / 1000;
	u64 ms = us / 1000;
	u64 s = ms / 1000;

	if (s > 10)
		snprintf(buf, len, "%llus", s);
	else if (ms > 10)
		snprintf(buf, len, "%llums", ms);
	else if (us > 10)
		snprintf(buf, len, "%lluus", us);
	else
		snprintf(buf, len, "%lluns", ns);

	return (s || ms > 10);
}

static inline void pr_ti(struct trace_info *ti, char *opt, char *delay)
{
	char comm[16];

	if (get_comm(ti->pid, comm))
		memcpy(comm, ti->comm, sizeof(comm));

	printf("%-27lluCPU=%-7dPID=%-7dCOMM=%-20s%-37s%-17s\n",
				ti->ts, ti->cpu, ti->pid, comm, opt,
				delay ? delay : "");
}

static int print_trace_info(int start, int end)
{
	int key;
	char d_str[16];
	char comm_buf[2*TASK_COMM_LEN];
	static u64 w_start, p_start;
	static struct trace_info ti_last;

	for (key = start; key != end; key = (key + 1) % NR_ENTRY_MAX) {
		char func[80];
		struct trace_info ti;
		struct si_key sik;
		u64 siv;

		if (bpf_map_lookup_elem(env.ti_map_fd, &key, &ti))
			continue;

		time_to_str(ti.ts - ti_last.ts, d_str, sizeof(d_str));

		switch (ti.type) {
		case TYPE_MIGRATE:
			w_start = p_start = ti.ts;
			pr_ti(&ti, "MIGRATE", NULL);
			break;
		case TYPE_ENQUEUE:
			w_start = p_start = ti.ts;
			printf("----------------------------\n");
			pr_ti(&ti, "ENQUEUE", NULL);
			break;
		case TYPE_WAIT:
			if (ti.pid == env.target) {
				w_start = ti.ts;
				pr_ti(&ti, "WAIT AFTER EXECUTED", d_str);
			} else {
				time_to_str(ti.ts - p_start,
						d_str, sizeof(d_str));
				pr_ti(&ti, "PREEMPTED", d_str);
			}
			break;
		case TYPE_EXECUTE:
			if (ti.pid == env.target) {
				time_to_str(ti.ts - w_start,
						d_str, sizeof(d_str));
				pr_ti(&ti, "EXECUTE AFTER WAITED", d_str);
			} else {
				p_start = ti.ts;
				pr_ti(&ti, "PREEMPT", NULL);
			}
			break;
		case TYPE_DEQUEUE:
			if (ti.pid == env.target)
				pr_ti(&ti, "DEQUEUE AFTER EXECUTED", d_str);
			else {
				time_to_str(ti.ts - p_start,
						d_str, sizeof(d_str));
				pr_ti(&ti, "DEQUEUE AFTER PREEMPTED", d_str);
			}
			break;
		case TYPE_SYSCALL_ENTER:
			siv = ti.ts;
			sik.cpu = ti.cpu;
			sik.pid = ti.pid;
			sik.syscall = ti.syscall;
			bpf_map_update_elem(env.si_map_fd, &sik, &siv, BPF_ANY);
			syscall_name(ti.syscall, comm_buf, sizeof(comm_buf));
			snprintf(func, sizeof(func), "SC [%d:%s] ENTER",
					ti.syscall, comm_buf);
			pr_ti(&ti, func, NULL);
			break;
		case TYPE_SYSCALL_EXIT:
			sik.cpu = ti.cpu;
			sik.pid = ti.pid;
			sik.syscall = ti.syscall;
			if (bpf_map_lookup_elem(env.si_map_fd, &sik, &siv))
				break;
			time_to_str(ti.ts - siv, d_str, sizeof(d_str));
			bpf_map_delete_elem(env.si_map_fd, &sik);
			syscall_name(ti.syscall, comm_buf, sizeof(comm_buf));
			snprintf(func, sizeof(func), "SC [%d:%s] TAKE %s TO EXIT",
					ti.syscall, comm_buf, d_str);
			pr_ti(&ti, func, NULL);
			break;
		default:
			break;
		}

		memcpy(&ti_last, &ti, sizeof(ti));
	}

	return end;
}

static int setup_user_info(int pid)
{
	int key = 0;
	DIR *dir;
	char buf[256];
	struct user_info ui;
	snprintf(buf, sizeof(buf), "/proc/%d", pid);
	dir = opendir(buf);
	if (!dir) {
		printf("Open %s failed: %s\n", buf, strerror(errno));
		return -1;
	}
	memset(&ui, 0, sizeof(ui));
	ui.pid = pid;
	ui.trace_syscall = env.trace_syscall;
	bpf_map_update_elem(env.ui_map_fd, &key, &ui, BPF_ANY);

	closedir(dir);

	return 0;
}

static void int_exit(int sig)
{
	env.exiting = true;
}

int main(int argc, char **argv)
{
	struct task_detector_bpf *obj;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	
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
	obj = task_detector_bpf__open();
	if(!obj){
		fprintf(stderr, "failed to open and/or load BPF object\n");
		goto freename;
	}

	/* Load bpf program */
	err = task_detector_bpf__load(obj);
	if(err){
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
	
	/* Attach bpf program */
	err = task_detector_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	/* Setup global map fd */
	env.ui_map_fd = bpf_map__fd(obj->maps.user_info_maps);
	env.ti_map_fd = bpf_map__fd(obj->maps.trace_info_maps);
	env.si_map_fd = bpf_map__fd(obj->maps.syscall_info_maps);
	env.start_map_fd = bpf_map__fd(obj->maps.start_maps);
	env.end_map_fd = bpf_map__fd(obj->maps.end_maps);

	/* Setip user info */
	if (setup_user_info(env.target)) {
		printf("Illegal Target %d\n", env.target);
		goto cleanup;
	}
	
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	printf("Start tracing schedule events ");
	if (env.trace_syscall)
		printf("(include SYSCALL)");
	printf("\nTarget task pid %d\n", env.target);
	
	/* main: print trace info */
	while (1) {
		if (env.exiting)
			goto cleanup;
		int key = 0, start = 0, end = 0;
		struct user_info ui = {
			.exit = 0,
		};

		bpf_map_lookup_elem(env.ui_map_fd, &key, &ui);
		if (ui.exit) {
			printf("Target \"%d\" Destroyed\n", env.target);
			goto cleanup;
		}

		bpf_map_lookup_elem(env.start_map_fd, &key, &start);
		bpf_map_lookup_elem(env.end_map_fd, &key, &end);
		if (start == end) {
			sleep(1);
			continue;
		}

		start = print_trace_info(start, end);

		bpf_map_update_elem(env.start_map_fd, &key, &start, BPF_ANY);
	}

cleanup:
	task_detector_bpf__destroy(obj);
freename:
	free_syscall_names();
	return err != 0;
}
