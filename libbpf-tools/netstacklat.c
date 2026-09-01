/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE // to get name_to_handle_at
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <argp.h>
#include <ctype.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timex.h>
#include <sys/stat.h>
#include <fts.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <linux/net_tstamp.h>

#include "netstacklat.h"
#include "netstacklat.skel.h"
#include "trace_helpers.h"

#define MAX_EPOLL_EVENTS 8

/*
 * Used to pack both a "type" and a value into the epoll_event.data.u64 member.
 * The topmost bits indicates the type (SIG, TIMER, etc) while the remaining
 * bits can be used for the value. The MASK can be used to filter out the
 * type/value.
 */
#define NETSTACKLAT_EPOLL_SIG (1ULL << 63)
#define NETSTACKLAT_EPOLL_TIMER (1ULL << 62)
#define NETSTACKLAT_EPOLL_TYPE_MASK \
	(NETSTACKLAT_EPOLL_SIG | NETSTACKLAT_EPOLL_TIMER)

// Magical value used to indicate that the program should be aborted
#define NETSTACKLAT_ABORT 424242

#define MAX_BUCKETSPAN_STRLEN 16
#define MAX_BUCKETCOUNT_STRLEN 10
#define MAX_BAR_STRLEN (80 - 6 - MAX_BUCKETSPAN_STRLEN - MAX_BUCKETCOUNT_STRLEN)

#define LOOKUP_BATCH_SIZE 128

#define MAX_HOOK_PROGS 4
#define MAX_CGROUP_PATH_MAPPINGS 65536

typedef int (*t_parse_val_func)(const char *, void *);

struct hook_prog_collection {
	struct bpf_program *progs[MAX_HOOK_PROGS];
	int nprogs;
};

struct histogram_entry {
	struct hist_key key;
	__u64 *current_buckets;
	__u64 *prev_buckets;
};

struct histogram_buffer {
	struct histogram_entry *hists;
	size_t max_size;
	size_t current_size;
};

struct id_name {
	__u64 id;
	char *name;
};

struct cgroup_idpath_map {
	char cgroup_path[PATH_MAX];
	struct id_name *idpath_map;
	size_t max_size; // max size of id_pathmap
	size_t current_size; // current size of idpath_map
	size_t searcheable; // subset of current_size that can be looked up
};

struct env {
	struct netstacklat_bpf_config bpf_conf;
	double report_interval_s;
	char *cgroups_str;
	bool has_enabled_hooks;
	bool has_disabled_hooks;
	bool translate_ifindex;
	bool enabled_hooks[NETSTACKLAT_N_HOOKS];
	int npids;
	int nifindices;
	int ncgroups;
	__u32 pids[MAX_PARSED_PIDS];
	__u32 ifindices[MAX_PARSED_IFACES];
	__u64 cgroups[MAX_PARSED_CGROUPS];
	struct cgroup_idpath_map cgroup_map;
};

static char cgroup_mount_path[PATH_MAX - 32] = "/sys/fs/cgroup";

const char *argp_program_version = "netstacklat 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Monitor latency at various points in the ingress network stack\n"
"\n"
"USAGE: netstacklat [--help] [-l] [-I] [-C] [-r SEC] [-e PROBES | -d PROBES]\n"
"                   [-i IFACES] [-c CGROUPS] [-p PIDS] [-n NETNS] [-q NUM]\n"
"                   [-m PATH] [-y]\n"
"\n"
"EXAMPLES:\n"
"    netstacklat            # trace ingress host network latency system-wide\n"
"    netstacklat -l         # list all available netstacklat probe points\n"
"    netstacklat -e PROBES  # only trace latency at PROBES\n"
"    netstacklat -d PROBES  # trace latency for all points expect PROBES\n"
"    netstacklat -r N       # print N second summeries\n"
"    netstacklat -I -C      # separate summeries for each interface and cgroup\n"
"    netstacklat -i IFACES  # filter for interface(s) IFACES\n"
"    netstacklat -c CGROUPS # filter for cgroup(s) CGROUPS\n";

static const struct argp_option opts[] = {
	{ "report-interval", 'r', "SEC", 0, "reporting interval in seconds",
	  0 },
	{ "include-hol-delay", 'y', NULL, 0,
	  "include delays from reads that are head-of-line blocked (only for tcp-socket-read)",
	  0 },
	{ "cgroup-mount", 'm', "PATH", 0,
	  "set the path to the cgroup mount (default /sys/fs/cgroup)", 0 },

	{ "Probe points:", 0, NULL, OPTION_DOC, NULL, 0 },
	{ "enable-probes", 'e', "PROBES", 0,
	  "comma-separated list of probes to include", 1 },
	{ "disable-probes", 'd', "PROBES", 0,
	  "comma-separated list of probes to exclude", 1 },
	{ "list-probes", 'l', NULL, 0, "list all probe points", 1 },

	{ "Filtering:", 0, NULL, OPTION_DOC, NULL, 1 },
	{ "pids", 'p', "PIDS", 0,
	  "comma-separated list of pids to include (only affects socket-read probes)",
	  2 },
	{ "cgroups", 'c', "CGROUPS", 0,
	  "comma-separated list of cgroups to include (only affects socket-read probes)",
	  2 },
	{ "interfaces", 'i', "IFACES", 0,
	  "comma-separated list of interfaces to include", 2 },
	{ "netns", 'n', "NETNS-ID", 0,
	  "network namespace identifier to monitor (-1 for all, 0 for current (default))",
	  2 },
	{ "min-queuelength", 'q', "NUM", 0,
	  "Only report socket reads when the socket receive queue is at least NUM SKBs",
	  2 },

	{ "Grouping:", 0, NULL, OPTION_DOC, NULL, 2 },
	{ "groupby-interface", 'I', NULL, 0, "group the results per interface",
	  3 },
	{ "groupby-cgroup", 'C', NULL, 0,
	  "group the results per cgroup (only affects socket-read probes)", 3 },
	{ "Info:", 0, NULL, OPTION_DOC, NULL, -2 },
	{ 0 },
};

static const struct argp_option *argp_opt_from_key(int key)
{
	int i;

	for (i = 0; opts[i].key != 0 || opts[i].flags != 0; i++) {
		if (opts[i].key == key)
			return &opts[i];
	}

	return NULL;
}

static const char *argp_name_from_key(int key)
{
	const struct argp_option *opt = argp_opt_from_key(key);

	return opt ? opt->name : "";
}

static const char *hook_to_str(enum netstacklat_hook hook)
{
	switch (hook) {
	case NETSTACKLAT_HOOK_IP_RCV:
		return "ip-start";
	case NETSTACKLAT_HOOK_TCP_START:
		return "tcp-start";
	case NETSTACKLAT_HOOK_UDP_START:
		return "udp-start";
	case NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED:
		return "tcp-socket-enqueued";
	case NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED:
		return "udp-socket-enqueued";
	case NETSTACKLAT_HOOK_TCP_SOCK_READ:
		return "tcp-socket-read";
	case NETSTACKLAT_HOOK_UDP_SOCK_READ:
		return "udp-socket-read";
	default:
		return "invalid";
	}
}

static enum netstacklat_hook str_to_hook(const char *str)
{
	enum netstacklat_hook hook;

	for (hook = 1; hook < NETSTACKLAT_N_HOOKS; hook++) {
		if (strcmp(str, hook_to_str(hook)) == 0)
			return hook;
	}

	return NETSTACKLAT_HOOK_INVALID;
}

static const char *hook_to_description(enum netstacklat_hook hook)
{
	switch (hook) {
	case NETSTACKLAT_HOOK_IP_RCV:
		return "packet has reached the IP-stack, i.e. past the traffic control layer";
	case NETSTACKLAT_HOOK_TCP_START:
		return "packet has reached the local TCP-stack, i.e. past the IP (and routing) stack";
	case NETSTACKLAT_HOOK_UDP_START:
		return "packet has reached the local UDP-stack, i.e. past the IP (and routing) stack";
	case NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED:
		return "packet has been enqueued to a TCP socket, i.e. end of the kernel receive stack";
	case NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED:
		return "packet has been enqueued to a UDP socket, i.e. end of the kernel receive stack";
	case NETSTACKLAT_HOOK_TCP_SOCK_READ:
		return "packet payload has been read from TCP socket, i.e. delivered to user space";
	case NETSTACKLAT_HOOK_UDP_SOCK_READ:
		return "packet payload has been read from UDP socket, i.e. delivered to user space";
	default:
		return "not a valid hook";
	}
}

static void hook_to_progs(struct hook_prog_collection *progs,
			  enum netstacklat_hook hook,
			  const struct netstacklat_bpf *obj)
{
	switch (hook) {
	case NETSTACKLAT_HOOK_IP_RCV:
		progs->progs[0] = obj->progs.netstacklat_ip_rcv_core;
		progs->progs[1] = obj->progs.netstacklat_ip6_rcv_core;
		progs->nprogs = 2;
		break;
	case NETSTACKLAT_HOOK_TCP_START:
		progs->progs[0] = obj->progs.netstacklat_tcp_v4_rcv;
		progs->progs[1] = obj->progs.netstacklat_tcp_v6_rcv;
		progs->nprogs = 2;
		break;
	case NETSTACKLAT_HOOK_UDP_START:
		progs->progs[0] = obj->progs.netstacklat_udp_rcv;
		progs->progs[1] = obj->progs.netstacklat_udpv6_rcv;
		progs->nprogs = 2;
		break;
	case NETSTACKLAT_HOOK_TCP_SOCK_ENQUEUED:
		progs->progs[0] = obj->progs.netstacklat_tcp_queue_rcv;
		progs->nprogs = 1;
		break;
	case NETSTACKLAT_HOOK_UDP_SOCK_ENQUEUED:
		progs->progs[0] =
			obj->progs.netstacklat_udp_enqueue_schedule_skb;
		progs->nprogs = 1;
		break;
	case NETSTACKLAT_HOOK_TCP_SOCK_READ:
		progs->progs[0] = obj->progs.netstacklat_tcp_recv_timestamp;
		progs->nprogs = 1;
		break;
	case NETSTACKLAT_HOOK_UDP_SOCK_READ:
		progs->progs[0] = obj->progs.netstacklat_skb_consume_udp;
		progs->nprogs = 1;
		break;
	default:
		progs->nprogs = 0;
		break;
	}
}

static void list_hooks(FILE *stream)
{
	enum netstacklat_hook hook;

	fprintf(stream, "available hooks:\n");
	for (hook = 1; hook < NETSTACKLAT_N_HOOKS; hook++)
		fprintf(stream, "  %s: %s\n", hook_to_str(hook),
			hook_to_description(hook));
}

static long long get_current_network_ns(void)
{
	struct stat ns_stat;
	int err;

	err = stat("/proc/self/ns/net", &ns_stat);
	if (err)
		return -errno;

	return ns_stat.st_ino;
}

static int parse_bounded_double(double *res, const char *str, double low,
				double high, const char *name)
{
	char *endptr;
	errno = 0;

	*res = strtod(str, &endptr);
	if (endptr == str || strlen(str) != endptr - str) {
		fprintf(stderr, "%s %s is not a valid number\n", name, str);
		return -EINVAL;
	}

	if (errno == ERANGE) {
		fprintf(stderr, "%s %s overflowed\n", name, str);
		return -ERANGE;
	}

	if (*res < low || *res > high || !isfinite(*res)) {
		fprintf(stderr, "%s must be in range [%g, %g]\n", name, low, high);
		return -ERANGE;
	}

	return 0;
}

static int parse_bounded_long(long long *res, const char *str, long long low,
			      long long high, const char *name)
{
	char *endptr;
	errno = 0;

	*res = strtoll(str, &endptr, 10);
	if (endptr == str || strlen(str) != endptr - str) {
		fprintf(stderr, "%s %s is not a valid integer\n", name, str);
		return -EINVAL;
	}

	if (errno == ERANGE) {
		fprintf(stderr, "%s %s overflowed\n", name, str);
		return -ERANGE;
	}

	if (*res < low || *res > high) {
		fprintf(stderr, "%s must be in range [%lld, %lld]\n", name, low,
			high);
		return -ERANGE;
	}

	return 0;
}

static int parse_strlist_to_arr(const char *_str, void *arr, size_t nelem,
				size_t elem_size, const char *delim,
				t_parse_val_func parse_func)
{
	char *tokstr, *str;
	char *saveptr = NULL;
	int err = 0, i = 0;

	str = malloc(strlen(_str) + 1);
	if (!str)
		return -ENOMEM;
	strcpy(str, _str);

	tokstr = strtok_r(str, delim, &saveptr);
	while (tokstr && i < nelem) {
		err = parse_func(tokstr, (char *)arr + i * elem_size);
		if (err)
			goto exit;

		tokstr = strtok_r(NULL, delim, &saveptr);
		i++;
	}

	if (tokstr)
		// Parsed size values, but more still remain
		err = -E2BIG;

exit:
	free(str);
	return err ?: i;
}

int parse_hook(const char *str, void *hookout)
{
	enum netstacklat_hook hook;

	hook = str_to_hook(str);
	if (hook == NETSTACKLAT_HOOK_INVALID) {
		fprintf(stderr, "%s is not a valid hook\n", str);
		return -EINVAL;
	}

	*(enum netstacklat_hook *)hookout = hook;
	return 0;
}

/*
 * Parses a comma-delimited string of hook-names, and sets the positions for
 * the hooks that appear in the string to true.
 */
static int parse_hooks(bool hooks[NETSTACKLAT_N_HOOKS], const char *str)
{
	enum netstacklat_hook ehooks[NETSTACKLAT_N_HOOKS * 2];
	int len, i;

	len = parse_strlist_to_arr(str, ehooks, ARRAY_SIZE(ehooks),
				   sizeof(*ehooks), ",", parse_hook);
	if (len < 0)
		return len;

	for (i = 0; i < NETSTACKLAT_N_HOOKS; i++)
		hooks[i] = false;

	for (i = 0; i < len; i++)
		hooks[ehooks[i]] = true;

	return 0;
}

static int parse_pid(const char *str, void *pidout)
{
	long long lval;
	int err;

	err = parse_bounded_long(&lval, str, 1, PID_MAX_LIMIT, "pid");
	if (err)
		return err;

	*(__u32 *)pidout = lval;
	return 0;
}

static int parse_pids(size_t size, __u32 arr[size], const char *str)
{
	return parse_strlist_to_arr(str, arr, size, sizeof(*arr), ",",
				    parse_pid);
}

static int parse_iface(const char *str, void *ifindexout)
{
	int ifindex, err = 0;
	long long lval;

	ifindex = if_nametoindex(str);
	if (ifindex > IFINDEX_MAX) {
		fprintf(stderr,
			"%s has ifindex %d which is above the supported limit %d\n",
			str, ifindex, IFINDEX_MAX);
		return -ENOTSUP;
	} else if (ifindex == 0) {
		// Not a valid interface name - try parsing it as an index instead
		err = parse_bounded_long(&lval, str, 1, IFINDEX_MAX,
					 "interface");
		if (!err)
			ifindex = lval;
	}

	if (ifindex > 0)
		*(__u32 *)ifindexout = ifindex;
	else
		fprintf(stderr,
			"%s is not a recognized interface name, nor a valid interface index\n",
			str);

	return err;
}

static int parse_ifaces(size_t size, __u32 arr[size], const char *str)
{
	return parse_strlist_to_arr(str, arr, size, sizeof(*arr), ",", parse_iface);
}

/**
 * get_cgroup_id_from_path - Get cgroup id for a particular cgroup path
 * @cgroup_workdir: The absolute cgroup path
 *
 * On success, it returns the cgroup id. On failure it returns 0,
 * which is an invalid cgroup id, and errno is set.
 *
 * Slightly modified version of get_cgroup_id_from_path from
 * /tools/testing/selftests/bpf/cgroup_helpers.c that does not
 * print out the errors
 */
static unsigned long long get_cgroup_id_from_path(const char *cgroup_workdir)
{
	int dirfd, err, flags, mount_id, fhsize;
	union {
		unsigned long long cgid;
		unsigned char raw_bytes[8];
	} id;
	struct file_handle *fhp, *fhp2;
	unsigned long long ret = 0;

	dirfd = AT_FDCWD;
	flags = 0;
	fhsize = sizeof(*fhp);
	fhp = calloc(1, fhsize);
	if (!fhp)
		return 0;

	err = name_to_handle_at(dirfd, cgroup_workdir, fhp, &mount_id, flags);
	if (err >= 0 || fhp->handle_bytes != 8) {
		if (err >= 0 || errno == EOVERFLOW)
			errno = EBADE;
		goto free_mem;
	}

	fhsize = sizeof(struct file_handle) + fhp->handle_bytes;
	fhp2 = realloc(fhp, fhsize);
	if (!fhp2)
		goto free_mem;

	err = name_to_handle_at(dirfd, cgroup_workdir, fhp2, &mount_id, flags);
	fhp = fhp2;
	if (err < 0)
		goto free_mem;

	memcpy(id.raw_bytes, fhp->f_handle, 8);
	ret = id.cgid;

free_mem:
	free(fhp);
	return ret;
}

static int parse_cgroup(const char *str, void *cgroupout)
{
	char full_cgroup_path[PATH_MAX];
	int len, err = 0;
	long long lval;
	__u64 cgroup;

	// assume relative path from cgroup_mount if not starting with /
	len = snprintf(full_cgroup_path, sizeof(full_cgroup_path), "%s/%s",
		       str[0] == '/' ? "" : cgroup_mount_path, str);
	if (len < 0)
		return -errno;
	else if (len >= sizeof(full_cgroup_path))
		return -E2BIG;

	cgroup = get_cgroup_id_from_path(full_cgroup_path);

	if (cgroup == 0) {
		// Not a valid cgroup path - try parse it as an int instead
		err = parse_bounded_long(&lval, str, 0, INT64_MAX, "cgroup");
		if (!err)
			cgroup = lval;
	}

	if (cgroup != 0)
		*(__u64 *)cgroupout = cgroup;
	else
		fprintf(stderr, "%s is not a valid cgroup path or ID\n", str);

	return err;
}

static int parse_cgroups(size_t size, __u64 arr[size], const char *str)
{
	return parse_strlist_to_arr(str, arr, size, sizeof(*arr), ",", parse_cgroup);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct env *env = state->input;
	long long lval;
	double fval;
	size_t size;
	int i, ret;
	char *buf;

	switch (key) {
	case 'r': // report-interval
		ret = parse_bounded_double(&fval, arg, 0.01, 3600 * 24,
					   argp_name_from_key(key));
		if (ret)
			goto err_parse_arg;

		env->report_interval_s = fval;
		break;
	case 'y': // include-hol-delay
		env->bpf_conf.include_hol_blocked = true;
		break;
	case 'm': // cgroup-mount
		if (arg[0] == '\0') {
			argp_error(state, "%s must be non-empty",
				   argp_name_from_key(key));
			return EINVAL;
		} else if (strlen(arg) >= sizeof(cgroup_mount_path)) {
			argp_error(state, "%s \"%s\"too long",
				   argp_name_from_key(key), arg);
			return E2BIG;
		}

		strcpy(cgroup_mount_path, arg);
		break;
	case 'e': // enable-probes
		if (env->has_disabled_hooks)
			goto err_enable_and_disable_probes;

		ret = parse_hooks(env->enabled_hooks, arg);
		if (ret)
			goto err_parse_arg;

		env->has_enabled_hooks = true;
		break;
	case 'd': // disable-probes
		if (env->has_enabled_hooks)
			goto err_enable_and_disable_probes;

		ret = parse_hooks(env->enabled_hooks, arg);
		if (ret)
			goto err_parse_arg;

		// invert enabled -> disabled
		for (i = 1; i < NETSTACKLAT_N_HOOKS; i++)
			env->enabled_hooks[i] = !env->enabled_hooks[i];

		env->has_disabled_hooks = true;
		break;
	case 'l': // list-probes
		list_hooks(stdout);
		exit(EXIT_SUCCESS); // return some code?
		break;
	case 'p': // pids
		ret = parse_pids(ARRAY_SIZE(env->pids) - env->npids,
				 env->pids + env->npids, arg);
		if (ret < 0)
			goto err_parse_arg;

		env->npids += ret;
		env->bpf_conf.filter_pid = true;
		break;
	case 'c': // cgroups
		/*
		 * Need to delay parsing cgroups until we can be certain that
		 * any --cgroup-mount option has been processed. Save the
		 * arguments to process later
		 */
		if (!env->cgroups_str) {
			// first time --cgroup option is provided
			env->cgroups_str = strdup(arg);
			if (!env->cgroups_str) {
				ret = errno;
				goto err_alloc;
			}
		} else {
			// cgroups have been provided previously - append
			size = strlen(env->cgroups_str) + strlen(arg) + 2;
			buf = malloc(size);
			if (!buf) {
				ret = errno;
				goto err_alloc;
			}

			snprintf(buf, size, "%s,%s", env->cgroups_str, arg);
			free(env->cgroups_str);
			env->cgroups_str = buf;
		}

		break;
	case 'i': // interfaces
		ret = parse_ifaces(ARRAY_SIZE(env->ifindices) - env->nifindices,
				   env->ifindices + env->nifindices, arg);
		if (ret < 0)
			goto err_parse_arg;

		env->nifindices += ret;
		env->bpf_conf.filter_ifindex = true;
		break;
	case 'n': // netns
		ret = parse_bounded_long(&lval, arg, -1, UINT32_MAX,
					 argp_name_from_key(key));
		if (ret)
			goto err_parse_arg;

		// include all netns (no filtering)
		if (lval < 0) {
			env->bpf_conf.network_ns = 0;
			/*
			 * Same ifindex can represent multiple interfaces in
			 * different netns. Cannot accurately map ifindex to
			 * an interface (and corresponding interface name).
			 */
			env->translate_ifindex = false;
		// use current netns
		} else if (lval == 0) {
			; // keep initialized value
		} else if (lval != env->bpf_conf.network_ns) {
			env->bpf_conf.network_ns = lval;
			/*
			 * No simple way to get ifindex to interface name
			 * in a different network namespace.
			 */
			env->translate_ifindex = false;
		}
		break;
	case 'q': // min-queuelength
		ret = parse_bounded_long(&lval, arg, 0, 65536,
					 argp_name_from_key(key));
		if (ret)
			goto err_parse_arg;

		env->bpf_conf.filter_min_sockqueue_len = lval;
		break;
	case 'I': // groupby-interface
		env->bpf_conf.groupby_ifindex = true;
		break;
	case 'C': // groupby-cgroup
		env->bpf_conf.groupby_cgroup = true;
		break;
	case ARGP_KEY_END:
		if (env->cgroups_str) {
			/* parse provided cgroups now that any cgroup-mount
			   option must have been handled.
			 */
			ret = parse_cgroups(ARRAY_SIZE(env->cgroups),
					    env->cgroups, env->cgroups_str);
			if (ret < 0) {
				key = 'c';
				goto err_parse_arg;
			}

			env->ncgroups = ret;
			env->bpf_conf.filter_cgroup = true;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;

err_parse_arg:
	argp_error(state, "failed parsing %s: %s", argp_name_from_key(key),
		   strerror(-ret));
	return -ret;
err_enable_and_disable_probes:
	argp_error(state, "%s and %s are mutually exclusive, only use one\n",
		   argp_name_from_key('e'), argp_name_from_key('d'));
	return EEXIST;
err_alloc:
	// Not a user error - so don't use argp_error()
	fprintf(stderr, "Failed to copy %s argument: %s\n",
		argp_name_from_key(key), strerror(ret));
	return ret;
}

static int parse_args(int argc, char *argv[], struct env *env)
{
	struct argp argp = { .options = opts,
			     .parser = parse_arg,
			     .doc = argp_program_doc };
	long long current_netns;
	int i;

	memset(env, 0, sizeof(*env));
	env->report_interval_s = 0;

	for (i = 0; i < NETSTACKLAT_N_HOOKS; i++)
		// All probes enabled by default
		env->enabled_hooks[i] = true;

	current_netns = get_current_network_ns();
	if (current_netns < 0) {
		fprintf(stderr,
			"Failed getting current network namespace: %s\n",
			strerror(-current_netns));
		return -current_netns;
	}
	env->bpf_conf.network_ns = current_netns;
	env->translate_ifindex = true;

	return -argp_parse(&argp, argc, argv, 0, NULL, env);
}

static void *insert_inorder(void *arr, void *elem, size_t size, size_t nmeb,
			    int(compar)(const void *, const void *))
{
	char *last_pos = arr + (nmeb * size), *pos = last_pos;

	while (pos > (char *)arr && compar(elem, pos - size) < 0)
		pos -= size;

	memmove(pos + size, pos, last_pos - pos);
	memcpy(pos, elem, size);

	return pos;
}

static int compare_cgroup_idpaths(const void *_id1, const void *_id2)
{
	const struct id_name *id1 = _id1, *id2 = _id2;
	if (id1->id == id2->id)
		return 0;
	return id1->id < id2->id ? -1 : 1;
}

static struct id_name *_lookup_cgroup_id(const struct cgroup_idpath_map *cgmap,
					 __u64 cgroup_id)
{
	return bsearch(&cgroup_id, cgmap->idpath_map, cgmap->searcheable,
		       sizeof(*cgmap->idpath_map), compare_cgroup_idpaths);
}

static void update_cgroup_idpath_map_searchable(struct cgroup_idpath_map *cgmap)
{
	if (cgmap->current_size > cgmap->searcheable)
		qsort(cgmap->idpath_map, cgmap->current_size,
		      sizeof(*cgmap->idpath_map), compare_cgroup_idpaths);
	cgmap->searcheable = cgmap->current_size;
}

static int add_cgroup_idpath(struct cgroup_idpath_map *cgmap, __u64 cgroup_id,
			     const char *cgroup_path, bool searchable)
{
	struct id_name cgroup;

	if (cgmap->current_size >= cgmap->max_size)
		return -ENOSPC;

	cgroup.id = cgroup_id;
	cgroup.name = strdup(cgroup_path);
	if (!cgroup.name)
		return -errno;

	if (searchable) {
		update_cgroup_idpath_map_searchable(cgmap);
		insert_inorder(cgmap->idpath_map, &cgroup, sizeof(cgroup),
			       cgmap->current_size++, compare_cgroup_idpaths);
		cgmap->searcheable++;
	} else {
		memcpy(&cgmap->idpath_map[cgmap->current_size++], &cgroup,
		       sizeof(cgroup));
	}

	return 0;
}

static int update_cgroup_idpath(struct cgroup_idpath_map *cgmap,
				__u64 cgroup_id, const char *cgroup_path,
				bool searchable)
{
	struct id_name *cgroup;
	char *newname;

	cgroup = _lookup_cgroup_id(cgmap, cgroup_id);
	if (!cgroup)
		return add_cgroup_idpath(cgmap, cgroup_id, cgroup_path,
					 searchable);

	// Update cgroup path for existing id-path mapping (if different)
	if (strcmp(cgroup->name, cgroup_path) == 0)
		return 0;

	newname = strdup(cgroup_path);
	if (!newname)
		return -errno;

	free(cgroup->name);
	cgroup->name = newname;

	return 0;
}

static int update_cgroup_idpath_map(struct cgroup_idpath_map *cgmap)
{
	char path_copy[sizeof(cgmap->cgroup_path)];
	char *root_paths[] = { path_copy, NULL };
	__u64 cgroup_id;
	FTS *fts_tree;
	FTSENT *dir;
	int err = 0;

	/*
	 * fts_open() does not garantuee that it won't modify the path.
	 * So need to copy the path argument.
	 * https://stackoverflow.com/a/65845045
	 */
	strncpy(path_copy, cgmap->cgroup_path, sizeof(path_copy));
	path_copy[sizeof(path_copy) - 1] = '\0';

	fts_tree = fts_open(root_paths, FTS_LOGICAL | FTS_NOSTAT, NULL);
	if (!fts_tree)
		return -errno;

	errno = 0;
	while ((dir = fts_read(fts_tree))) {
		if (dir->fts_info == FTS_ERR) {
			err = -dir->fts_errno;
			break;
		} else if (dir->fts_info != FTS_D)
			continue;

		cgroup_id = get_cgroup_id_from_path(dir->fts_path);
		if (!cgroup_id) {
			if (errno == ENOENT) {
				/*
				 * Probably a cgroup that got deleted before
				 * we could get its ID.
				 * Ignore and move on.
				 */
				errno = 0;
				continue;
			} else {
				err = -errno;
				break;
			}
		}

		err = update_cgroup_idpath(cgmap, cgroup_id, dir->fts_path,
					   false);
		if (err)
			break;
	}
	// catch potential errno from fts_read()
	err = err ?: -errno;

	fts_close(fts_tree);
	update_cgroup_idpath_map_searchable(cgmap);
	return err;
}

static struct id_name *lookup_cgroup_id(struct cgroup_idpath_map *cgmap,
					__u64 cgroup_id, bool allow_rescan,
					bool *did_rescan)
{
	struct id_name *cgroup;
	int err;

	cgroup = _lookup_cgroup_id(cgmap, cgroup_id);
	if (cgroup || !allow_rescan) {
		if (did_rescan)
			*did_rescan = false;
		return cgroup;
	}

	err = update_cgroup_idpath_map(cgmap);
	if (err) {
		errno = -err;
		return NULL;
	}

	if (did_rescan)
		*did_rescan = true;
	return _lookup_cgroup_id(cgmap, cgroup_id);
}

static void free_cgroup_idpath(struct id_name *entry)
{
	free(entry->name);
	entry->name = NULL;
}

static void free_cgroup_idpath_map(struct cgroup_idpath_map *cgmap)
{
	while (cgmap->current_size > 0)
		free_cgroup_idpath(&cgmap->idpath_map[--cgmap->current_size]);

	cgmap->searcheable = 0;
	free(cgmap->idpath_map);
	cgmap->idpath_map = NULL;
}

static int init_cgroup_idpath_map(struct cgroup_idpath_map *cgmap,
				  size_t max_size, const char *cgroup_path)
{
	int err;

	memset(cgmap, 0, sizeof(*cgmap));
	cgmap->max_size = max_size;

	if (strlen(cgroup_path) >= sizeof(cgmap->cgroup_path))
		return -E2BIG;
	strcpy(cgmap->cgroup_path, cgroup_path);

	cgmap->idpath_map = calloc(max_size, sizeof(*cgmap->idpath_map));
	if (!cgmap->idpath_map)
		return -errno;

	err = update_cgroup_idpath_map(cgmap);
	if (err) {
		free_cgroup_idpath_map(cgmap);
		return err;
	}

	return 0;
}

static double ns_to_siprefix(double ns, const char **prefix)
{
	static char *prefixes[] = { "n", "u", "m", "" };
	int psteps = 0;

	while (ns >= 1000 && psteps < ARRAY_SIZE(prefixes) - 1) {
		ns /= 1000;
		psteps++;
	}

	*prefix = prefixes[psteps];

	return ns;
}

static void format_nanosecond_delay(char *buf, size_t size,
				    unsigned long long delay)
{
	const char *prefix;
	double sival;

	sival = ns_to_siprefix(delay, &prefix);
	snprintf(buf, size, "%.3g%ss", sival, prefix);
}

/*
 * Get the left edge of a log2-le (less-than-or-equal) histogram bin.
 *
 * In an log2-le hist, the bin index is obtained from ceil(log2(val)), which
 * gives right-closed bins of the format (2^(i - 1), 2^i].
 */
unsigned long long log2_le_bin_edge(size_t bin, void *ctx)
{
	return bin < 1 ? 0 : (1ULL << (bin - 1)) + 1;
}

static int format_ifindex(__u32 ifindex, bool translate_to_name, char *buf,
			  size_t size)
{
	int len;

	// just format as a number
	if (!translate_to_name) {
		len = snprintf(buf, size, "%u", ifindex);
		return len < 0 ? -errno : len >= size ? -E2BIG : 0;
	}

	// translate to ifname
	if (size < IF_NAMESIZE)
		return -E2BIG;
	if (!if_indextoname(ifindex, buf))
		return -errno;

	return 0;
}

static int format_cgroup(__u64 cgroup_id, struct cgroup_idpath_map *cgmap,
			 bool *has_rescanned, char *buf, size_t size)
{
	struct id_name *cgroup;
	int len;

	cgroup = lookup_cgroup_id(cgmap, cgroup_id, !*has_rescanned,
				  *has_rescanned ? NULL : has_rescanned);
	if (!cgroup) {
		len = snprintf(buf, size, "unknown (%llu)", cgroup_id);
		if (len >= 0)
			update_cgroup_idpath(cgmap, cgroup_id, buf, true);
	} else {
		len = snprintf(buf, size, "%s", cgroup->name);
	}

	return len < 0 ? -errno : len >= size ? -E2BIG : 0;
}

static void print_histkey(const struct hist_key *key, struct env *env,
			  bool *has_rescanned)
{
	char buf[PATH_MAX];

	printf("%s", hook_to_str(key->hook));

	if (key->ifindex) {
		if (format_ifindex(key->ifindex, env->translate_ifindex, buf,
				   sizeof(buf)) != 0)
			snprintf(buf, sizeof(buf), "%u", key->ifindex);
		printf(", interface=%s", buf);
	}

	if (key->cgroup) {
		format_cgroup(key->cgroup, &env->cgroup_map, has_rescanned, buf,
			      sizeof(buf));
		printf(", cgroup=%s", buf);
	}
}

static __u64 diff_histentry(struct histogram_entry *entry, size_t n,
			    __u32 diff[n - 1], __u64 *sum)
{
	__u64 count = 0;
	int i;

	for (i = 0; i < n - 1; i++) {
		diff[i] = entry->current_buckets[i] - entry->prev_buckets[i];
		entry->prev_buckets[i] = entry->current_buckets[i];
		count += diff[i];
	}

	// The last "bucket" is actually a sum
	*sum = entry->current_buckets[n - 1] - entry->prev_buckets[n - 1];
	entry->prev_buckets[n - 1] = entry->current_buckets[n - 1];

	return count;
}

static void print_histentry(struct histogram_entry *entry, struct env *env,
			    bool *has_rescanned)
{
	__u32 diff[HIST_NBUCKETS - 1];
	const char *prefix;
	__u64 count, sum;
	double avg;

	count = diff_histentry(entry, HIST_NBUCKETS, diff, &sum);
	// Skip reporting entires with no change (empty histogram)
	if (!count)
		return;

	print_histkey(&entry->key, env, has_rescanned);
	printf(":\n");

	print_hist(diff, ARRAY_SIZE(diff), "delay", log2_le_bin_edge, NULL,
		   format_nanosecond_delay, false);

	// Final "bucket" is the sum of all values in the histogram
	if (count > 0) {
		avg = ns_to_siprefix((double)sum / count, &prefix);
		printf("count: %llu, average: %.2f%ss\n", count, avg, prefix);
	} else {
		printf("count: %llu, average: -\n", count);
	}
	printf("\n");
}

static int cmp_histkey(const void *val1, const void *val2)
{
	const struct hist_key *key1 = val1, *key2 = val2;

	if (key1->hook != key2->hook)
		return key1->hook > key2->hook ? 1 : -1;

	if (key1->ifindex != key2->ifindex)
		return key1->ifindex > key2->ifindex ? 1 : -1;

	if (key1->cgroup != key2->cgroup)
		return key1->cgroup > key2->cgroup ? 1 : -1;

	return 0;
}

static int cmp_histentry(const void *val1, const void *val2)
{
	const struct histogram_entry *entry1 = val1, *entry2 = val2;

	return cmp_histkey(&entry1->key, &entry2->key);
}

static struct histogram_entry *
lookup_or_zeroinit_hist(const struct hist_key *key,
			struct histogram_buffer *buf)
{
	struct histogram_entry new_hist, *hist;
	__u64 *current_buckets, *prev_buckets;

	hist = bsearch(key, buf->hists, buf->current_size, sizeof(*buf->hists),
		       cmp_histentry);
	if (hist)
		return hist;

	// No matching histogram key found - create new histogram entry and insert it
	if (buf->current_size >= buf->max_size) {
		errno = ENOSPC;
		return NULL;
	}

	current_buckets = calloc(HIST_NBUCKETS, sizeof(*current_buckets));
	prev_buckets = calloc(HIST_NBUCKETS, sizeof(*prev_buckets));
	if (!current_buckets || !prev_buckets) {
		errno = ENOMEM;
		goto err;
	}

	memcpy(&new_hist.key, key, sizeof(hist->key));
	new_hist.key.bucket = 0;
	new_hist.current_buckets = current_buckets;
	new_hist.prev_buckets = prev_buckets;

	return insert_inorder(buf->hists, &new_hist, sizeof(new_hist),
			      buf->current_size++, cmp_histentry);
err:
	free(current_buckets);
	free(prev_buckets);
	return NULL;
}

static void free_histentry(struct histogram_entry *hist)
{
	free(hist->current_buckets);
	free(hist->prev_buckets);
	hist->current_buckets = NULL;
	hist->prev_buckets = NULL;
}

static int update_histogram_entry_bucket(const struct hist_key *key,
					 __u64 count,
					 struct histogram_buffer *buf)
{
	struct histogram_entry *hist;
	int bucket = key->bucket;

	if (bucket >= HIST_NBUCKETS)
		return -ERANGE;

	hist = lookup_or_zeroinit_hist(key, buf);
	if (!hist)
		return -errno;

	hist->current_buckets[bucket] = count;
	return 0;
}

static __u64 sum_percpu_vals(int cpus, __u64 vals[cpus])
{
	__u64 sum = 0;
	int i;

	for (i = 0; i < cpus; i++)
		sum += vals[i];

	return sum;
}

static int fetch_histograms(int map_fd, struct histogram_buffer *buf)
{
	__u32 in_batch, out_batch, count = LOOKUP_BATCH_SIZE;
	int ncpus = libbpf_num_possible_cpus();
	int i, nentries = 0, err, err2 = 0;
	__u64(*percpu_buckets)[ncpus];
	bool entries_remain = true;
	struct hist_key *keys;

	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, batch_opts);

	percpu_buckets = calloc(LOOKUP_BATCH_SIZE, sizeof(*percpu_buckets));
	keys = calloc(LOOKUP_BATCH_SIZE, sizeof(*keys));
	if (!percpu_buckets || !keys) {
		err = -ENOMEM;
		goto exit;
	}

	while (entries_remain) {
		err = bpf_map_lookup_batch(map_fd,
					   nentries > 0 ? &in_batch : NULL,
					   &out_batch, keys, percpu_buckets,
					   &count, &batch_opts);
		if (err == -ENOENT) { // All entries fetched
			entries_remain = false;
			err = 0;
		} else if (err) {
			goto exit;
		}

		for (i = 0; i < count; i++) {
			err = update_histogram_entry_bucket(
				&keys[i],
				sum_percpu_vals(ncpus, percpu_buckets[i]), buf);
			if (err == -ENOSPC) {
				/*
				 * Out of histogram entries.
				 * Record error, but continue.
				 * Use error code that should not clash with
				 * bpf_map_lookup_batch
				 */
				err2 = -ETOOMANYREFS;
				err = 0;
			} else if (err) {
				// Critical error - abort
				goto exit;
			}
		}

		nentries += count;
		count = LOOKUP_BATCH_SIZE;
		in_batch = out_batch;
	}

exit:
	free(percpu_buckets);
	free(keys);
	return err ?: err2;
}

static int report_stats(struct env *env, const struct netstacklat_bpf *obj,
			struct histogram_buffer *hist_buf)
{
	bool has_rescanned = false;
	int i, err;
	time_t t;

	err = fetch_histograms(bpf_map__fd(obj->maps.netstack_latency_seconds),
			       hist_buf);
	if (err == -ETOOMANYREFS)
		fprintf(stderr,
			"Warning: Histogram buffer ran out of space - some histograms may not be reported\n");
	else if (err)
		return err;

	time(&t);
	printf("%s", ctime(&t));

	for (i = 0; i < hist_buf->current_size; i++) {
		print_histentry(&hist_buf->hists[i], env, &has_rescanned);
	}
	fflush(stdout);

	return 0;
}

static int init_histogram_buffer(struct histogram_buffer *buf,
				 const struct env *env)
{
	int max_hists = 0, i;

	for (i = 0; i < NETSTACKLAT_N_HOOKS; i++) {
		if (env->enabled_hooks[i])
			max_hists++;
	}

	if (env->bpf_conf.groupby_ifindex)
		max_hists *= env->bpf_conf.filter_ifindex ?
				     min(env->nifindices, 64) :
				     32;

	if (env->bpf_conf.groupby_cgroup)
		max_hists *= env->bpf_conf.filter_cgroup ?
				     min(env->ncgroups, 128) :
				     64;

	buf->hists = calloc(max_hists, sizeof(*buf->hists));
	if (!buf->hists)
		return -errno;

	buf->max_size = max_hists;
	buf->current_size = 0;
	return 0;
}

static void free_histogram_buffer(struct histogram_buffer *buf)
{
	while (buf->current_size > 0)
		free_histentry(&buf->hists[--buf->current_size]);

	free(buf->hists);
	buf->hists = NULL;
}

static int enable_sw_rx_tstamps(void)
{
	int tstamp_opt = SOF_TIMESTAMPING_RX_SOFTWARE;
	int sock_fd, err;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed opening socket: %s\n", strerror(-err));
		return err;
	}

	err = setsockopt(sock_fd, SOL_SOCKET, SO_TIMESTAMPING, &tstamp_opt,
			 sizeof(tstamp_opt));
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed setting SO_TIMESTAMPING option: %s\n",
			strerror(-err));
		goto err_socket;
	}

	return sock_fd;

err_socket:
	close(sock_fd);
	return err;
}

static __s64 get_tai_offset(void)
{
	struct ntptimeval ntpt;

	ntp_gettimex(&ntpt);
	return ntpt.tai;
}

static const char *bpf_program__function_name(const struct bpf_program *prog)
{
	const char *sec = bpf_program__section_name(prog);
	int i;

	if (!sec || strlen(sec) == 0)
		return NULL;

	for (i = strlen(sec) - 1; i > 0; i--)
		if (sec[i] == '/')
			return &sec[i + 1];

	return sec;
}

static int set_program_loadable(struct netstacklat_bpf *obj,
				struct bpf_program *prog, bool try_load)
{
	if (try_load &&
	    !fentry_can_attach(bpf_program__function_name(prog), NULL)) {
		/*
		 * Some netstacklat probes have both IPv4 and IPv6 paths.
		 * On kernels lacking IPv6 support, it is ok to just disable
		 * the IPv6 path and rely on just the IPv4 path. However,
		 * if non-IPv6 functions cannot be attached to, the
		 * netstacklat hook point will not function properly.
		 */
		if (prog != obj->progs.netstacklat_ip6_rcv_core &&
		    prog != obj->progs.netstacklat_tcp_v6_rcv &&
		    prog != obj->progs.netstacklat_udpv6_rcv)
			return -ESRCH;

		try_load = false;
	}

	bpf_program__set_autoload(prog, try_load);
	return 0;
}

static int set_programs_to_load(const struct env *env,
				struct netstacklat_bpf *obj)
{
	struct hook_prog_collection progs;
	enum netstacklat_hook hook;
	struct bpf_program *prog;
	int i, err;

	for (hook = 1; hook < NETSTACKLAT_N_HOOKS; hook++) {
		hook_to_progs(&progs, hook, obj);

		for (i = 0; i < progs.nprogs; i++) {
			prog = progs.progs[i];

			err = set_program_loadable(obj, prog,
						   env->enabled_hooks[hook]);
			if (err) {
				fprintf(stderr,
					"Cannot attach program to %s, probe %s not supported\n",
					bpf_program__section_name(prog),
					hook_to_str(hook));
				return err;
			}
		}
	}

	return 0;
}

static int set_map_sizes(const struct env *env,
			 struct netstacklat_bpf *obj, int max_hists)
{
	__u32 size;
	int err, i;

	size = max_hists * HIST_NBUCKETS;
	err = bpf_map__set_max_entries(obj->maps.netstack_latency_seconds,
				       size);
	if (err) {
		fprintf(stderr, "Failed setting size of histogram map to %u\n",
			size);
		return err;
	}

	// PID filter - arraymap, needs max PID + 1 entries
	for (i = 0, size = 1; i < env->npids; i++) {
		if (env->pids[i] >= size)
			size = env->pids[i] + 1;
	}
	err = bpf_map__set_max_entries(obj->maps.netstack_pidfilter, size);
	if (err) {
		fprintf(stderr, "Failed setting size of PID filter map to %u\n",
			size);
		return err;
	}

	// ifindex filter - arraymap, needs max ifindex + 1 entries
	for (i = 0, size = 1; i < env->nifindices; i++) {
		if (env->ifindices[i] >= size)
			size = env->ifindices[i] + 1;
	}
	err = bpf_map__set_max_entries(obj->maps.netstack_ifindexfilter, size);
	if (err) {
		fprintf(stderr,
			"Failed setting size of ifindex filter map to %u\n",
			size);
		return err;
	}

	// cgroup filter - hashmap, should be ~2x expected number of entries
	size = env->bpf_conf.filter_cgroup ? env->ncgroups * 2 : 1;
	err = bpf_map__set_max_entries(obj->maps.netstack_cgroupfilter, size);
	if (err) {
		fprintf(stderr,
			"Failed setting size of cgroup filter map to %u\n",
			size);
		return err;
	}

	return 0;
}

static int init_filtermap(int map_fd, void *keys, size_t nelem,
			  size_t elem_size)
{
	__u64 ok_val = 1;
	int i, err;

	for (i = 0; i < nelem; i++) {
		err = bpf_map_update_elem(map_fd, (char *)keys + i * elem_size,
					  &ok_val, 0);
		if (err)
			return err;
	}

	return 0;
}

static int init_signalfd(void)
{
	sigset_t mask;
	int fd, err;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	fd = signalfd(-1, &mask, 0);
	if (fd < 0)
		return -errno;

	err = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (err) {
		close(fd);
		return -err;
	}

	return fd;
}

static int handle_signal(int sig_fd)
{
	struct signalfd_siginfo sig_info;
	ssize_t size;

	size = read(sig_fd, &sig_info, sizeof(sig_info));
	if (size != sizeof(sig_info)) {
		fprintf(stderr, "Failed reading signal fd\n");
		return -EBADFD;
	}

	switch (sig_info.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		return NETSTACKLAT_ABORT;
	default:
		fprintf(stderr, "Unexpected signal: %d\n", sig_info.ssi_signo);
		return -EBADR;
	}
}

static int setup_timer(__u64 interval_ns)
{
	struct itimerspec timercfg = {
		.it_value = { .tv_sec = interval_ns / NS_PER_S,
			      .tv_nsec = interval_ns % NS_PER_S },
		.it_interval = { .tv_sec = interval_ns / NS_PER_S,
				 .tv_nsec = interval_ns % NS_PER_S }
	};
	int fd, err;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		return -errno;
	}

	err = timerfd_settime(fd, 0, &timercfg, NULL);
	if (err) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

static int handle_timer(int timer_fd, struct env *env,
			const struct netstacklat_bpf *obj,
			struct histogram_buffer *hist_buf)
{
	__u64 timer_exps;
	ssize_t size;

	size = read(timer_fd, &timer_exps, sizeof(timer_exps));
	if (size != sizeof(timer_exps)) {
		fprintf(stderr, "Failed reading timer fd\n");
		return -EBADFD;
	}

	if (timer_exps == 0)
		return 0;
	if (timer_exps > 1)
		fprintf(stderr, "Warning: Missed %llu reporting intervals\n",
			timer_exps - 1);

	return report_stats(env, obj, hist_buf);
}

static int epoll_add_event(int epoll_fd, int fd, __u64 event_type, __u64 value)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data = { .u64 = event_type | value },
	};

	if (value & NETSTACKLAT_EPOLL_TYPE_MASK)
		return -EINVAL;

	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) ? -errno : 0;
}

static int setup_epoll_instance(int sig_fd, int timer_fd)
{
	int epoll_fd, err = 0;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0)
		return -errno;

	err = epoll_add_event(epoll_fd, sig_fd, NETSTACKLAT_EPOLL_SIG, sig_fd);
	if (err)
		goto err;

	err = epoll_add_event(epoll_fd, timer_fd, NETSTACKLAT_EPOLL_TIMER,
			      timer_fd);
	if (err)
		goto err;

	return epoll_fd;

err:
	close(epoll_fd);
	return err;
}

static int poll_events(int epoll_fd, struct env *env,
		       const struct netstacklat_bpf *obj,
		       struct histogram_buffer *hist_buf)
{
	struct epoll_event events[MAX_EPOLL_EVENTS];
	int i, n, fd, err = 0;
	__u64 epoll_type;

	n = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 100);
	if (n < 0)
		return -errno;

	for (i = 0; i < n; i++) {
		epoll_type = events[i].data.u64 & NETSTACKLAT_EPOLL_TYPE_MASK;
		fd = events[i].data.u64 & ~NETSTACKLAT_EPOLL_TYPE_MASK;

		switch (epoll_type) {
		case NETSTACKLAT_EPOLL_SIG:
			err = handle_signal(fd);
			break;
		case NETSTACKLAT_EPOLL_TIMER:
			err = handle_timer(fd, env, obj, hist_buf);
			break;
		default:
			fprintf(stderr, "Warning: unexpected epoll data: %lu\n",
				events[i].data.u64);
			break;
		}

		if (err)
			break;
	}

	return err;
}

int main(int argc, char *argv[])
{
	int sig_fd, timer_fd, epoll_fd, sock_fd, err;
	struct env env;
	struct histogram_buffer hist_buf;
	struct netstacklat_bpf *obj;
	char errmsg[128];

	err = parse_args(argc, argv, &env);
	if (err) {
		fprintf(stderr, "Failed parsing arguments: %s\n",
			strerror(err));
		return EXIT_FAILURE;
	}

	err = init_histogram_buffer(&hist_buf, &env);
	if (err) {
		fprintf(stderr, "Failed allocating buffer for histograms: %s\n",
			strerror(-err));
		return EXIT_FAILURE;
	}

	if (env.bpf_conf.groupby_cgroup) {
		err = init_cgroup_idpath_map(&env.cgroup_map,
					   MAX_CGROUP_PATH_MAPPINGS,
					   cgroup_mount_path);
		if (err) {
			fprintf(stderr, "Failed scanning cgroups at %s: %s\n",
				cgroup_mount_path, strerror(-err));
			return EXIT_FAILURE;
		}
	}

	sock_fd = enable_sw_rx_tstamps();
	if (sock_fd < 0) {
		err = sock_fd;
		fprintf(stderr,
			"Failed enabling software RX timestamping: %s\n",
			strerror(-err));
		return EXIT_FAILURE;
	}

	obj = netstacklat_bpf__open();
	if (!obj) {
		err = -errno;
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed opening eBPF object file: %s\n", errmsg);
		goto exit_sockfd;
	}

	obj->rodata->TAI_OFFSET = get_tai_offset() * NS_PER_S;
	obj->rodata->user_config = env.bpf_conf;

	err = set_programs_to_load(&env, obj);
	if (err) {
		fprintf(stderr, "Failed configuring programs to load: %s\n",
			strerror(-err));
		goto exit_destroy_bpf;
	}

	err = set_map_sizes(&env, obj, hist_buf.max_size);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed configuring map sizes: %s\n", errmsg);
		goto exit_destroy_bpf;
	}

	err = netstacklat_bpf__load(obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed loading eBPF programs: %s\n", errmsg);
		goto exit_destroy_bpf;
	}

	err = init_filtermap(bpf_map__fd(obj->maps.netstack_pidfilter),
			     env.pids, env.npids, sizeof(*env.pids));

	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed filling the pid filter map: %s\n",
			errmsg);
		goto exit_destroy_bpf;
	}

	err = init_filtermap(bpf_map__fd(obj->maps.netstack_ifindexfilter),
			     env.ifindices, env.nifindices,
			     sizeof(*env.ifindices));
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed filling the ifindex filter map: %s\n",
			errmsg);
		goto exit_destroy_bpf;
	}

	err = init_filtermap(bpf_map__fd(obj->maps.netstack_cgroupfilter),
			     env.cgroups, env.ncgroups,
			     sizeof(*env.cgroups));
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed filling the cgroup filter map: %s\n",
			errmsg);
		goto exit_destroy_bpf;
	}

	err = netstacklat_bpf__attach(obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Failed to attach eBPF programs: %s\n", errmsg);
		goto exit_destroy_bpf;
	}

	sig_fd = init_signalfd();
	if (sig_fd < 0) {
		err = sig_fd;
		fprintf(stderr, "Failed setting up signal handling: %s\n",
			strerror(-err));
		goto exit_detach_bpf;
	}

	timer_fd = setup_timer(env.report_interval_s * NS_PER_S);
	if (timer_fd < 0) {
		err = timer_fd;
		fprintf(stderr, "Failed creating timer: %s\n", strerror(-err));
		goto exit_sigfd;
	}

	epoll_fd = setup_epoll_instance(sig_fd, timer_fd);
	if (epoll_fd < 0) {
		err = epoll_fd;
		fprintf(stderr, "Failed setting up epoll: %s\n",
			strerror(-err));
		goto exit_timerfd;
	}

	// Report stats until user shuts down program
	while (true) {
		err = poll_events(epoll_fd, &env, obj, &hist_buf);

		if (err) {
			if (err == NETSTACKLAT_ABORT) {
				// Report stats a final time before terminating
				err = report_stats(&env, obj, &hist_buf);
			} else {
				libbpf_strerror(err, errmsg, sizeof(errmsg));
				fprintf(stderr, "Failed polling fds: %s\n",
					errmsg);
			}
			break;
		}
	}

	// Cleanup
	close(epoll_fd);
exit_timerfd:
	close(timer_fd);
exit_sigfd:
	close(sig_fd);
exit_detach_bpf:
	netstacklat_bpf__detach(obj);
exit_destroy_bpf:
	netstacklat_bpf__destroy(obj);
exit_sockfd:
	close(sock_fd);
	free_cgroup_idpath_map(&env.cgroup_map);
	free_histogram_buffer(&hist_buf);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
