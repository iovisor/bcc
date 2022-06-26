// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Ze Gao
 *
 * Based on funcslower from BCC by Sasha Goldshtein and others
 * 2022-06-17   Ze Gao   Created this.
 */

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "btf_helpers.h"
#include "funcslower.h"
#include "funcslower.skel.h"
#include "map_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

#define MAX_NUM_FUNCS 12

static struct prog_env {
        pid_t pid;
        int units;
        int args;
        __u64 duration;
        char *cgroupspath;
        char *funcnames[MAX_NUM_FUNCS];
        int num_funcs;
        bool cg;
        bool ustack;
        bool kstack;
        bool timestamp;
        bool verbose;
        // statically reconfigurable
        int stack_storage_size;
        int perf_buffer_pages;
        int perf_max_stack_depth;
        int perf_poll_timeout_ms;
        // runtime envs
        __u64 earliest_ts;
        int stack_map_fd;
        struct syms_cache *syms_cache;
        struct ksyms *ksyms;
        unsigned long *ip;
        struct bpf_link *links[2 * MAX_NUM_FUNCS];
        int num_links;
} env = {
    .pid = -1,
    .duration = 1000000, // defaults to 1ms
    .num_funcs = 0,
    .stack_storage_size = 1024,
    .perf_buffer_pages = 64,
    .perf_max_stack_depth = 127,
    .perf_poll_timeout_ms = 100,
    .earliest_ts = 0,
    .stack_map_fd = -1,
    .ip = NULL,
    .num_links = 0,
};

const char *argp_program_version = "funcslower 0.1";
const char *argp_program_bug_address =
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
static const char args_doc[] = "FUNCTION";
static const char program_doc[] =
    "Trace slow kernel or user function calls.\n"
    "\n"
    "USAGE: funcslower [-h] [-p PID] [-m MIN_MS] [-u MIN_US] [-a ARGUMENTS]\n"
    "                   [-T] [-v] FUNCTION [FUNCTION]\n"
    "       Choices for FUNCTION: FUNCTION         (kprobe)\n"
    "                             LIBRARY:FUNCTION (uprobe a library in -p "
    "PID)\n"
    "                             :FUNCTION        (uprobe the binary of -p "
    "PID)\n"
    "                             PROGRAM:FUNCTION (uprobe the binary "
    "PROGRAM)\n"
    "\v"
    "Examples:\n"
    "  ./funcslower vfs_write        # trace vfs_write calls slower than 1ms\n"
    "  ./funcslower -m 10 vfs_write  # same, but slower than 10ms\n"
    "  ./funcslower -u 10 c:open     # trace open calls slower than 10us\n"
    "  ./funcslower -p 135 c:open    # trace pid 135 only\n"
    "  ./funcslower c:malloc c:free  # trace both malloc and free slower than "
    "1ms\n"
    "  ./funcslower -a 2 c:open      # show first two arguments to open\n"
    "  ./funcslower -UK -m 10 c:open # Show user and kernel stack frame of open"
    "                                        calls slower than 10ms\n"
    "  ./funcslower -f -UK c:open    # Output in folded format for flame "
    "graphs\n";

static const struct argp_option opts[] = {
    {"milliseconds", 'm', "MIN_MS", 0, "Output in milliseconds"},
    {"microseconds", 'u', "MIN_US", 0, "Output in microseconds"},
    {0, 0, 0, 0, ""},
    {"cgroup", 'c', "/sys/fs/cgroup/unified", 0,
     "Trace process in cgroup path"},
    {"pid", 'p', "PID", 0, "Process ID to trace"},
    {"arguments", 'a', "ARGUMENTS", 0,
     "Show first ARGUMENTS arguments to the probed function"},
    {"ustack", 'U', NULL, 0, "Show user stack of the probed function"},
    {"kstack", 'K', NULL, 0, "Show user stack of the probed function"},
    {"timestamp", 'T', NULL, 0, "Print timestamp"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
        long duration, pid;
        int num_args;
        struct prog_env *env = state->input;

        switch (key) {
        case 'a':
                errno = 0;
                num_args = strtol(arg, NULL, 10);
                if (errno || num_args < 0 || num_args > MAX_NUM_ARGS) {
                        warn("Invalid Number Of Args: %s\n", arg);
                        argp_usage(state);
                }
                env->args = num_args;
                break;
        case 'c':
                env->cgroupspath = arg;
                env->cg = true;
                break;
        case 'p':
                errno = 0;
                pid = strtol(arg, NULL, 10);
                if (errno || pid <= 0) {
                        warn("Invalid PID: %s\n", arg);
                        argp_usage(state);
                }
                env->pid = pid;
                break;
        case 'm':
                if (env->units != NSEC) {
                        warn("only set one of -m or -u\n");
                        argp_usage(state);
                }
                env->units = MSEC;
                errno = 0;
                duration = strtol(arg, NULL, 10);
                if (errno || duration <= 0) {
                        warn("Invalid duration: %s\n", arg);
                        argp_usage(state);
                }
                env->duration = duration * 1000000;
                break;
        case 'u':
                if (env->units != NSEC) {
                        warn("only set one of -m or -u\n");
                        argp_usage(state);
                }
                env->units = USEC;
                errno = 0;
                duration = strtol(arg, NULL, 10);
                if (errno || duration <= 0) {
                        warn("Invalid duration: %s\n", arg);
                        argp_usage(state);
                }
                env->duration = duration * 1000;
                break;
        case 'T':
                env->timestamp = true;
                break;
        case 'U':
                env->ustack = true;
                break;
        case 'K':
                env->kstack = true;
                break;
        case 'v':
                env->verbose = true;
                break;
        case 'h':
                argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
                break;
        case ARGP_KEY_ARG:
                if (env->num_funcs >= MAX_NUM_FUNCS) {
                        warn("Too many function names, currently max support "
                             "number is %d\n",
                             MAX_NUM_FUNCS);
                        argp_usage(state);
                }
                env->funcnames[env->num_funcs++] = arg;
                break;
        case ARGP_KEY_END:
                if (!env->num_funcs) {
                        warn("Need a function to trace\n");
                        argp_usage(state);
                }
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}
static const char *unit_str(void) {
        switch (env.units) {
        case NSEC:
                return "nsec";
        case USEC:
                return "usec";
        case MSEC:
                return "msec";
        };
        return "bad units";
}
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
        if (level == LIBBPF_DEBUG && !env.verbose)
                return 0;
        return vfprintf(stderr, format, args);
}

static int attach_kprobes(struct funcslower_bpf *obj, const char *funcname,
                          int cookie) {
        LIBBPF_OPTS(bpf_kprobe_opts, opts);
        struct bpf_link *link = NULL;
        long err;

        opts.bpf_cookie = cookie;
        opts.retprobe = false;

        link = bpf_program__attach_kprobe_opts(obj->progs.dummy_kprobe,
                                               funcname, &opts);
        if (!link) {
                err = -errno;
                warn("failed to attach kprobe: %ld\n", err);
                return -1;
        }
        env.links[env.num_links++] = link;

        opts.retprobe = true;
        link = bpf_program__attach_kprobe_opts(obj->progs.dummy_kretprobe,
                                               funcname, &opts);
        if (!link) {
                err = -errno;
                warn("failed to attach kretprobe: %ld\n", err);
                return -1;
        }
        env.links[env.num_links++] = link;

        return 0;
}

static int attach_uprobes(struct funcslower_bpf *obj, const char *funcname,
                          int cookie) {
        LIBBPF_OPTS(bpf_uprobe_opts, opts);
        struct bpf_link *link = NULL;
        char *binary, *function;
        char bin_path[PATH_MAX];
        off_t func_off;
        int ret = -1;
        long err;

        binary = strdup(funcname);
        if (!binary) {
                warn("strdup failed");
                return -1;
        }
        function = strchr(binary, ':');
        if (!function) {
                warn("Binary should have contained ':' (internal bug!)\n");
                goto out_binary;
        }
        *function = '\0';
        function++;

        if (resolve_binary_path(binary, env.pid, bin_path, sizeof(bin_path)))
                goto out_binary;

        func_off = get_elf_func_offset(bin_path, function);
        if (func_off < 0) {
                warn("Could not find %s in %s\n", function, bin_path);
                goto out_binary;
        }

        opts.bpf_cookie = cookie;
        opts.retprobe = false;
        link = bpf_program__attach_uprobe_opts(
            obj->progs.dummy_kprobe, env.pid ?: -1, bin_path, func_off, &opts);
        if (!link) {
                err = -errno;
                warn("Failed to attach uprobe: %ld\n", err);
                goto out_binary;
        }
        env.links[env.num_links++] = link;

        opts.retprobe = true;
        link = bpf_program__attach_uprobe_opts(obj->progs.dummy_kretprobe,
                                               env.pid ?: -1, bin_path,
                                               func_off, &opts);
        if (!link) {
                err = -errno;
                warn("Failed to attach uretprobe: %ld\n", err);
                goto out_binary;
        }
        env.links[env.num_links++] = link;

        ret = 0;

out_binary:
        free(binary);

        return ret;
}

static int attach_probes(struct funcslower_bpf *obj, const char *funcname,
                         int cookie) {
        if (strchr(funcname, ':'))
                return attach_uprobes(obj, funcname, cookie);
        return attach_kprobes(obj, funcname, cookie);
}

static inline void print_sym(unsigned long ip, const void *syms, bool kernel) {
        const struct ksym *ksym;
        const struct sym *sym;

        if (kernel) {
                ksym = ksyms__map_addr((struct ksyms *)syms, ip);
                printf("    %s\n", ksym ? ksym->name : "[unknown]");
        } else {
                sym = syms__map_addr((struct syms *)syms, ip);
                printf("    %s\n", sym ? sym->name : "[unknown]");
        }
}

static void print_ustack(struct syms_cache *syms_cache, unsigned long tgid,
                         unsigned long *ip, int depth, bool reversed) {
        const struct syms *syms;
        syms = syms_cache__get_syms(syms_cache, tgid);

        if (!syms) {
                fprintf(stderr, "failed to get syms\n");
                return;
        }

        if (!reversed) {
                for (int k = 0; k < depth; k++) {
                        if (ip[k])
                                print_sym(ip[k], syms, 0);
                }
        } else {
                for (int k = depth - 1; k >= 0; k--) {
                        if (ip[k])
                                print_sym(ip[k], syms, 0);
                }
        }
}

static void print_kstack(struct ksyms *ksyms, unsigned long *ip, int depth,
                         bool reversed) {
        if (!reversed) {
                for (int k = 0; k < depth; k++) {
                        if (ip[k])
                                print_sym(ip[k], ksyms, 1);
                }
        } else {
                for (int k = depth - 1; k >= 0; k--) {
                        if (ip[k])
                                print_sym(ip[k], ksyms, 1);
                }
        }
}

static volatile bool exiting;

static void sig_hand(int signr) { exiting = true; }

static struct sigaction sigact = {.sa_handler = sig_hand};

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
        printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
        struct data_t *event = data;
        double duration;

        if (env.timestamp) {
                if (env.earliest_ts == 0)
                        env.earliest_ts = event->start_ns;
                printf("%-10.6f ",
                       ((event->start_ns - env.earliest_ts) / 1000000000.0));
        }
        switch (env.units) {
        case NSEC:
                duration = event->duration_ns / 1.0;
                break;
        case USEC:
                duration = event->duration_ns / 1000.0;
                break;
        case MSEC:
                duration = event->duration_ns / 1000000.0;
                break;
        default:
                warn("bad units");
        };

        printf("%-14.14s %-8d %7.2f %8llx %s", event->comm,
               (int)((event->tgid) >> 32), duration, event->retval,
               env.funcnames[event->id]);
        for (int i = 0; i < env.args; ++i) {
                printf(" %llx ", event->args[i]);
        }
        printf("\n");

        if (env.kstack || env.ustack) {
                if (!env.ip) {
                        env.ip = calloc(env.perf_max_stack_depth,
                                        sizeof(unsigned long));
                        if (!env.ip) {
                                fprintf(stderr, "failed to alloc ip\n");
                                return;
                        }
                }
                if (env.kstack) {
                        if (bpf_map_lookup_elem(env.stack_map_fd,
                                                &event->kstack, env.ip) != 0) {
                                fprintf(stderr, "    [Missed Kernel Stack]\n");
                        }
                        print_kstack(env.ksyms, env.ip,
                                     env.perf_max_stack_depth, 0);
                }
                if (env.ustack) {
                        if (bpf_map_lookup_elem(env.stack_map_fd,
                                                &event->ustack, env.ip) != 0) {
                                fprintf(stderr, "    [Missed User Stack]\n");
                        }
                        print_ustack(env.syms_cache, event->tgid, env.ip,
                                     env.perf_max_stack_depth, 0);
                }
        }
}

int main(int argc, char **argv) {

        LIBBPF_OPTS(bpf_object_open_opts, open_opts);
        int err;
        int idx, cg_map_fd;
        int cgfd = -1;
        struct funcslower_bpf *obj = NULL;
        struct perf_buffer *pb = NULL;
        static const struct argp argp = {
            .options = opts,
            .parser = parse_arg,
            .args_doc = args_doc,
            .doc = program_doc,
        };

        err = argp_parse(&argp, argc, argv, 0, NULL, &env);
        if (err)
                return err;

        sigaction(SIGINT, &sigact, 0);

        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        libbpf_set_print(libbpf_print_fn);

        env.ksyms = ksyms__load();
        if (!env.ksyms) {
                fprintf(stderr, "failed to load kallsyms\n");
                goto cleanup;
        }
        env.syms_cache = syms_cache__new(0);
        if (!env.syms_cache) {
                fprintf(stderr, "failed to create syms_cache\n");
                goto cleanup;
        }

        err = ensure_core_btf(&open_opts);
        if (err) {
                fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n",
                        strerror(-err));
                goto cleanup;
        }

        obj = funcslower_bpf__open_opts(&open_opts);
        if (!obj) {
                warn("failed to open BPF object\n");
                goto cleanup;
        }

        obj->rodata->duration = env.duration;
        obj->rodata->targ_tgid = env.pid;
        obj->rodata->filter_cg = env.cg;
        obj->rodata->show_kstack = env.kstack;
        obj->rodata->show_ustack = env.ustack;
        obj->rodata->num_args = env.args;
        bpf_map__set_value_size(obj->maps.stackmap, env.perf_max_stack_depth *
                                                        sizeof(unsigned long));
        bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);

        err = funcslower_bpf__load(obj);
        if (err) {
                warn("failed to load BPF object\n");
                goto cleanup;
        }
	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			fprintf(stderr,
					"Failed opening Cgroup path: %s",
					env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd,
					BPF_ANY)) {
			fprintf(stderr,
					"Failed adding target cgroup to map");
			goto cleanup;
		}
	}

        for (int i = 0; i < env.num_funcs; ++i) {
                err = attach_probes(obj, env.funcnames[i], i);
                if (err)
                        goto cleanup;
        }

        env.stack_map_fd = bpf_map__fd(obj->maps.stackmap);
        pb = perf_buffer__new(bpf_map__fd(obj->maps.events),
                              env.perf_buffer_pages, handle_event,
                              handle_lost_events, &env, NULL);
        if (!pb) {
                err = -errno;
                fprintf(stderr, "failed to open perf buffer: %d\n", err);
                goto cleanup;
        }

        if (env.timestamp)
                printf("%-10s", "TIME");
        printf("%-14s %-8s %4s%2s%1s %8s %s\n", "COMM", "PID", "LAT(",
               unit_str(), ")", "RVAL", env.args ? "FUNC(ARGS)" : "FUNC()");

        while (!exiting) {
                err = perf_buffer__poll(pb, env.perf_poll_timeout_ms);
                if (err < 0 && err != -EINTR) {
                        fprintf(stderr, "error polling perf buffer: %d\n", err);
                        goto cleanup;
                }
                /* reset err to return 0 if exiting */
                err = 0;
        }

cleanup:
        if (pb)
                perf_buffer__free(pb);
        if (env.syms_cache)
                syms_cache__free(env.syms_cache);
        if (env.ksyms)
                ksyms__free(env.ksyms);
        if (env.ip)
                free(env.ip);
        for (int i = 0; i < env.num_links; ++i)
                bpf_link__destroy(env.links[i]);
        if (obj)
                funcslower_bpf__destroy(obj);
        cleanup_core_btf(&open_opts);
        if (cgfd > 0)
                close(cgfd);
        return err != 0;
}
