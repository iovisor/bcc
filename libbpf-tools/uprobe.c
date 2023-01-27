#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "uprobe.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#define PATH_MAX 4096

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

static struct env {
	bool verbose;
	int perf_max_stack_depth;
	int stack_max_entries;
} env = {
	.verbose = false,
	.perf_max_stack_depth = 127,
	.stack_max_entries = 1024,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	struct uprobe_bpf *skel = NULL;
	pid_t parent_pid = -1;
	pid_t child_pid = -1;

	parent_pid = getpid();
	printf("parent pid: %d\n", parent_pid);

	//child_pid = fork();
	//switch(child_pid) {
	//	case -1:
	//		fprintf(stderr, "failed to fork child process\n");
	//		goto cleanup;
	//		break;
	//	case 0:
	//		if (execl("a.out", "a.out", NULL)) {
	//			fprintf(stderr, "failed to exec child program\n");
	//			goto cleanup;
	//			break;
	//		}
	//		break;
	//	default:
	//		printf("child pid: %d\n", child_pid);
	//		break;
	//}

	char resolved_path[PATH_MAX];
	if (resolve_binary_path("", parent_pid, resolved_path, sizeof(resolved_path))) {
		fprintf(stderr, "failed to resolve binry path\n");
		goto cleanup;
	}
	printf("resolved path: %s\n", resolved_path);

	off_t func_offset = get_elf_func_offset(resolved_path, "malloc");
	if (func_offset < 0) {
		fprintf(stderr, "failed to find func offset\n");
		goto cleanup;
	}
	printf("func offset: %ld\n", func_offset);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	skel = uprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open bpf object\n");
		return 1;
	}

	if (uprobe_bpf__load(skel)) {
		fprintf(stderr, "failed to load bpf object\n");
		goto cleanup;
	}

	skel->links.malloc_enter = bpf_program__attach_uprobe(
			skel->progs.malloc_enter,
			false,
			0,
			resolved_path,
			func_offset);
	if (!skel->links.malloc_enter) {
		fprintf(stderr, "failed to attach uprobe for malloc_enter\n");
		goto cleanup;
	}
	printf("attached uprobe\n");

	if (uprobe_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach bpf program(s)\n");
		goto cleanup;
	}
	printf("attached program\n");

cleanup:
	if (child_pid > 0) {
		printf("start waiting on child\n");
		wait(NULL);
		printf("done waiting on child\n");
	}

	uprobe_bpf__destroy(skel);

	printf("done\n");

	return 0;
}
