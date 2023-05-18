// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on ttysnoop.py 2016 Brendan Gregg.
//
#include <sys/stat.h>
#include <sys/utsname.h>
#include <argp.h>
#include <signal.h>
#include <stdlib.h>
#include <bpf/btf.h>
#include "ttysnoop.h"
#include "ttysnoop.skel.h"
#include "btf_helpers.h"
#include "compat.h"

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool verbose;
	bool clear_screen;
	int count;
	int pts_inode;
} env = {
	.clear_screen = true,
	.pts_inode = -1,
	.count = 16,
};

#define warning(...) fprintf(stderr, __VA_ARGS__)

const char *argp_program_version = "ttysnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Watch live output from a tty or pts device.\n"
"\n"
"USAGE:   ttysnoop [-Ch] {PTS | /dev/ttydev}  # try -h for help\n"
"\n"
"Example:\n"
"    ttysnoop /dev/pts/2          # snoop output from /dev/pts/2\n"
"    ttysnoop 2                   # snoop output from /dev/pts/2 (shortcut)\n"
"    ttysnoop /dev/console        # snoop output from the system console\n"
"    ttysnoop /dev/tty0           # snoop output from /dev/tty0\n"
"    ttysnoop /dev/pts/2 -c 2     # snoop output from /dev/pts/2 with 2 checks\n"
"                                   for 256 bytes of data in buffer\n"
"                                   (potentially retrieving 512 bytes)\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "datacount", 'c', "COUNT", 0, "Number of times we check for 'data-size' data (default 16)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
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
	case 'C':
		env.clear_screen = false;
		break;
	case 'c':
		errno = 0;
		env.count = strtol(arg, NULL, 10);
		if (errno || env.count <= 0) {
			warning("Error count: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG: {
		if (state->arg_num != 0) {
			warning("Unrecognized positional arguments: %s\n", arg);
			argp_usage(state);
		}

		char path[4096] = {};
		struct stat st;

		if (arg[0] != '/') {
			strcpy(path, "/dev/pts/");
			strcat(path, arg);
		} else {
			strcpy(path, arg);
		}

		if (stat(path, &st)) {
			warning("Failed to stat console file: %s\n", arg);
			argp_usage(state);
		}
		env.pts_inode = st.st_ino;
		break;
	}
	case ARGP_KEY_END:
		if (env.pts_inode == -1)
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	printf("%s", e->buf);
	fflush(stdout);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}

static bool fallback_to_compare_kernel_version(void)
{
	struct utsname sys_info;
	int major1, minor1, patch1;
	int major2, minor2, patch2;
	const char *version = "5.10.11";

	uname(&sys_info);

	sscanf(sys_info.release, "%d.%d.%d%*s", &major1, &minor1, &patch1);
	sscanf(version, "%d.%d.%d%*s", &major2, &minor2, &patch2);

	if (major1 < major2)
		return false;
	else if (major1 > major2)
		return true;

	if (minor1 < minor2)
		return false;
	else if (minor1 > minor2)
		return true;

	if (patch1 < patch2)
		return false;
	else if (patch1 > patch2)
		return true;

	return false;
}

static bool tty_write_is_newly(void)
{
	const struct btf_type *type;
	__s32 id;
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!btf) {
		warning("No BTF, cannot determine type info: %s", strerror(errno));
		goto failed;
	}

	id = btf__find_by_name_kind(btf, "tty_write", BTF_KIND_FUNC);
	if (id <= 0) {
		warning("Can't find function tty_write in BTF: %s\n",
			strerror(-id));
		goto failed;
	}

	type = btf__type_by_id(btf, id);
	if (!type || BTF_INFO_KIND(type->info) != BTF_KIND_FUNC)
		goto failed;

	type = btf__type_by_id(btf, type->type);
	if (!type || BTF_INFO_KIND(type->info) != BTF_KIND_FUNC_PROTO)
		goto failed;

	btf__free(btf);
	/* the newly tty_write has 2 params, old have 4 params */
	if (btf_vlen(type) != 2)
		return false;
	return true;

failed:
	return fallback_to_compare_kernel_version();
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ttysnoop_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err;
	bool new_tty_write = false;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	new_tty_write = tty_write_is_newly();
	libbpf_set_print(libbpf_print_fn);

	obj = ttysnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->user_data_count = env.count;
	obj->rodata->pts_inode = env.pts_inode;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (new_tty_write)
		bpf_program__set_autoload(obj->progs.kprobe__tty_write_old, false);
	else
		bpf_program__set_autoload(obj->progs.kprobe__tty_write_new, false);

	err = ttysnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = ttysnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.clear_screen) {
		err = system("clear");
		if (err)
			goto cleanup;
	}

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			break;
		}
		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	ttysnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
