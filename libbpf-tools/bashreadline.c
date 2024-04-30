/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Facebook */
#include <argp.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bashreadline.h"
#include "bashreadline.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "bashreadline 1.0";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Print entered bash commands from all running shells.\n"
"\n"
"USAGE: bashreadline [-s <path/to/libreadline.so>]\n"
"\n"
"EXAMPLES:\n"
"    bashreadline\n"
"    bashreadline -s /usr/lib/libreadline.so\n";

static const struct argp_option opts[] = {
	{ "shared", 's', "PATH", 0, "the location of libreadline.so library", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static char *libreadline_path = NULL;
static bool verbose = false;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 's':
		libreadline_path = strdup(arg);
		if (libreadline_path == NULL)
			return ARGP_ERR_UNKNOWN;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct str_t *e = data;
	struct tm *tm;
	char ts[16];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%m:%S", tm);

	printf("%-9s %-7d %s\n", ts, e->pid, e->str);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static char *find_readline_function_name(const char *bash_path)
{
  bool found = false;
  int fd = -1;
  Elf *elf = NULL;
  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;


  elf = open_elf(bash_path, &fd);

  while ((scn = elf_nextscn(elf, scn)) != NULL && !found) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
      Elf_Data *data = elf_getdata(scn, NULL);
      if (data != NULL) {
        GElf_Sym *symtab = (GElf_Sym *) data->d_buf;
        int sym_count = shdr.sh_size / shdr.sh_entsize;
        for (int i = 0; i < sym_count; ++i) {
          if(strcmp("readline_internal_teardown", elf_strptr(elf, shdr.sh_link, symtab[i].st_name)) == 0){
            found = true;
            break;
          }
        }
    	}
    }
  }

  close_elf(elf,fd);
  if (found)
    return "readline_internal_teardown";
  else
    return "readline";
}

static char *find_readline_so()
{
	const char *bash_path = "/bin/bash";
	FILE *fp;
	off_t func_off;
	char *line = NULL;
	size_t line_sz = 0;
	char path[128];
	char *result = NULL;

	func_off = get_elf_func_offset(bash_path, find_readline_function_name(bash_path));
	if (func_off >= 0)
		return strdup(bash_path);

	/*
	 * Try to find libreadline.so if readline is not defined in
	 * bash itself.
	 *
	 * ldd will print a list of names of shared objects,
	 * dependencies, and their paths.  The line for libreadline
	 * would looks like
	 *
	 *      libreadline.so.8 => /usr/lib/libreadline.so.8 (0x00007b....)
	 *
	 * Here, it finds a line with libreadline.so and extracts the
	 * path after the arrow, '=>', symbol.
	 */
	fp = popen("ldd /bin/bash", "r");
	if (fp == NULL)
		goto cleanup;
	while (getline(&line, &line_sz, fp) >= 0) {
		if (sscanf(line, "%*s => %127s", path) < 1)
			continue;
		if (strstr(line, "/libreadline.so")) {
			result = strdup(path);
			break;
		}
	}

cleanup:
	if (line)
		free(line);
	if (fp)
		pclose(fp);
	return result;
}

static void sig_int(int signo)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bashreadline_bpf *obj = NULL;
	struct perf_buffer *pb = NULL;
	char *readline_so_path;
	off_t func_off;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if (libreadline_path) {
		readline_so_path = libreadline_path;
	} else if ((readline_so_path = find_readline_so()) == NULL) {
		warn("failed to find readline\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		goto cleanup;
	}

	obj = bashreadline_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		goto cleanup;
	}

	err = bashreadline_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	func_off = get_elf_func_offset(readline_so_path, find_readline_function_name(readline_so_path));
	if (func_off < 0) {
		warn("cound not find readline in %s\n", readline_so_path);
		goto cleanup;
	}

	obj->links.printret = bpf_program__attach_uprobe(obj->progs.printret, true, -1,
							 readline_so_path, func_off);
	if (!obj->links.printret) {
		err = -errno;
		warn("failed to attach readline: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("%-9s %-7s %s\n", "TIME", "PID", "COMMAND");
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	if (readline_so_path)
		free(readline_so_path);
	perf_buffer__free(pb);
	bashreadline_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
