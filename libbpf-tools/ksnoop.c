/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "ksnoop.h"
#include "ksnoop.skel.h"

#ifndef KSNOOP_VERSION
#define KSNOOP_VERSION	"0.1"
#endif

static volatile sig_atomic_t exiting = 0;

static struct btf *vmlinux_btf;
static const char *bin_name;
static int pages = PAGES_DEFAULT;

enum log_level {
	DEBUG,
	WARN,
	ERROR,
};

static enum log_level log_level = WARN;
static bool verbose = false;

static __u32 filter_pid;
static bool stack_mode;


static void __p(enum log_level level, char *level_str, char *fmt, ...)
{
	va_list ap;

	if (level < log_level)
		return;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", level_str);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	fflush(stderr);
}

#define p_err(fmt, ...)		__p(ERROR, "Error", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...)	__p(WARNING, "Warn", fmt, ##__VA_ARGS__)
#define	p_debug(fmt, ...)	__p(DEBUG, "Debug", fmt, ##__VA_ARGS__)

static int do_version(int argc, char **argv)
{
	printf("%s v%s\n", bin_name, KSNOOP_VERSION);
	return 0;
}

static int cmd_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] [COMMAND | help] FUNC\n"
		"	COMMAND	:= { trace | info }\n"
		"	FUNC	:= { name | name(ARG[,ARG]*) }\n"
		"	ARG	:= { arg | arg [PRED] | arg->member [PRED] }\n"
		"	PRED	:= { == | != | > | >= | < | <=  value }\n"
		"	OPTIONS	:= { {-d|--debug} | {-v|--verbose} | {-V|--version} |\n"
		"                    {-p|--pid filter_pid}|\n"
		"                    {-P|--pages nr_pages} }\n"
		"                    {-s|--stack}\n",
		bin_name);
	fprintf(stderr,
		"Examples:\n"
		"	%s info ip_send_skb\n"
		"	%s trace ip_send_skb\n"
		"	%s trace \"ip_send_skb(skb, return)\"\n"
		"	%s trace \"ip_send_skb(skb->sk, return)\"\n"
		"	%s trace \"ip_send_skb(skb->len > 128, skb)\"\n"
		"	%s trace -s udp_sendmsg ip_send_skb\n",
		bin_name, bin_name, bin_name, bin_name, bin_name, bin_name);
	return 0;
}

static void usage(void)
{
	cmd_help(0, NULL);
	exit(1);
}

static void type_to_value(struct btf *btf, char *name, __u32 type_id,
			  struct value *val)
{
	const struct btf_type *type;
	__s32 id = type_id;

	if (strlen(val->name) == 0) {
		if (name)
			strncpy(val->name, name,
				sizeof(val->name) - 1);
		else
			val->name[0] = '\0';
	}
	do {
		type = btf__type_by_id(btf, id);

		switch (BTF_INFO_KIND(type->info)) {
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
			id = type->type;
			break;
		case BTF_KIND_PTR:
			val->flags |= KSNOOP_F_PTR;
			id = type->type;
			break;
		default:
			val->type_id = id;
			goto done;
		}
	} while (id >= 0);

	val->type_id = KSNOOP_ID_UNKNOWN;
	return;
done:
	val->size = btf__resolve_size(btf, val->type_id);
}

static int member_to_value(struct btf *btf, const char *name, __u32 type_id,
			   struct value *val, int lvl)
{
	const struct btf_member *member;
	const struct btf_type *type;
	const char *pname;
	__s32 id = type_id;
	int i, nmembers;
	__u8 kind;

	/* type_to_value has already stripped qualifiers, so
	 * we either have a base type, a struct, union, etc.
	 * Only struct/unions have named members so anything
	 * else is invalid.
	 */
	p_debug("Looking for member '%s' in type id %d", name, type_id);
	type = btf__type_by_id(btf, id);
	pname = btf__str_by_offset(btf, type->name_off);
	if (strlen(pname) == 0)
		pname = "<anon>";

	kind = BTF_INFO_KIND(type->info);
	switch (kind) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		nmembers = BTF_INFO_VLEN(type->info);
		p_debug("Checking %d members...", nmembers);
		for (member = (struct btf_member *)(type + 1), i = 0;
		     i < nmembers;
		     member++, i++) {
			const char *mname;
			__u16 offset;

			type = btf__type_by_id(btf, member->type);
			mname = btf__str_by_offset(btf, member->name_off);
			offset = member->offset / 8;

			p_debug("Checking member '%s' type %d offset %d",
				mname, member->type, offset);

			/* anonymous struct member? */
			kind = BTF_INFO_KIND(type->info);
			if (strlen(mname) == 0 &&
			    (kind == BTF_KIND_STRUCT ||
			     kind == BTF_KIND_UNION)) {
				p_debug("Checking anon struct/union %d",
					member->type);
				val->offset += offset;
				if (!member_to_value(btf, name, member->type,
						     val, lvl + 1))
					return 0;
				val->offset -= offset;
				continue;
			}

			if (strcmp(mname, name) == 0) {
				val->offset += offset;
				val->flags |= KSNOOP_F_MEMBER;
				type_to_value(btf, NULL, member->type, val);
				p_debug("Member '%s', offset %d, flags %x size %d",
					mname, val->offset, val->flags,
					val->size);
				return 0;
			}
		}
		if (lvl > 0)
			break;
		p_err("No member '%s' found in %s [%d], offset %d", name, pname,
		      id, val->offset);
		break;
	default:
		p_err("'%s' is not a struct/union", pname);
		break;
	}
	return -ENOENT;
}

static int get_func_btf(struct btf *btf, struct func *func)
{
	const struct btf_param *param;
	const struct btf_type *type;
	__u8 i;

	func->id = btf__find_by_name_kind(btf, func->name, BTF_KIND_FUNC);
	if (func->id <= 0) {
		p_err("Cannot find function '%s' in BTF: %s",
		       func->name, strerror(-func->id));
		return -ENOENT;
	}
	type = btf__type_by_id(btf, func->id);
	if (!type || BTF_INFO_KIND(type->info) != BTF_KIND_FUNC) {
		p_err("Error looking up function type via id '%d'", func->id);
		return -EINVAL;
	}
	type = btf__type_by_id(btf, type->type);
	if (!type || BTF_INFO_KIND(type->info) != BTF_KIND_FUNC_PROTO) {
		p_err("Error looking up function proto type via id '%d'",
		      func->id);
		return -EINVAL;
	}
	for (param = (struct btf_param *)(type + 1), i = 0;
	     i < BTF_INFO_VLEN(type->info) && i < MAX_ARGS;
	     param++, i++) {
		type_to_value(btf,
			      (char *)btf__str_by_offset(btf, param->name_off),
			      param->type, &func->args[i]);
		p_debug("arg #%d: <name '%s', type id '%u'>",
			i + 1, func->args[i].name, func->args[i].type_id);
	}

	/* real number of args, even if it is > number we recorded. */
	func->nr_args = BTF_INFO_VLEN(type->info);

	type_to_value(btf, KSNOOP_RETURN_NAME, type->type,
		      &func->args[KSNOOP_RETURN]);
	p_debug("return value: type id '%u'>",
		func->args[KSNOOP_RETURN].type_id);
	return 0;
}

static int predicate_to_value(char *predicate, struct value *val)
{
	char pred[MAX_STR];
	long v;

	if (!predicate)
		return 0;

	p_debug("checking predicate '%s' for '%s'", predicate, val->name);

	if (sscanf(predicate, "%[!=><]%li", pred, &v) != 2) {
		p_err("Invalid specification; expected predicate, not '%s'",
		      predicate);
		return -EINVAL;
	}
	if (!(val->flags & KSNOOP_F_PTR) &&
	    (val->size == 0 || val->size > sizeof(__u64))) {
		p_err("'%s' (size %d) does not support predicate comparison",
		      val->name, val->size);
		return -EINVAL;
	}
	val->predicate_value = (__u64)v;

	if (strcmp(pred, "==") == 0) {
		val->flags |= KSNOOP_F_PREDICATE_EQ;
		goto out;
	} else if (strcmp(pred, "!=") == 0) {
		val->flags |= KSNOOP_F_PREDICATE_NOTEQ;
		goto out;
	}
	if (pred[0] == '>')
		val->flags |= KSNOOP_F_PREDICATE_GT;
	else if (pred[0] == '<')
		val->flags |= KSNOOP_F_PREDICATE_LT;

	if (strlen(pred) == 1)
		goto out;

	if (pred[1] != '=') {
		p_err("Invalid predicate specification '%s'", predicate);
		return -EINVAL;
	}
	val->flags |= KSNOOP_F_PREDICATE_EQ;

out:
	p_debug("predicate '%s', flags 0x%x value %x",
		pred, val->flags, val->predicate_value);

	return 0;
}

static int trace_to_value(struct btf *btf, struct func *func, char *argname,
			  char *membername, char *predicate, struct value *val)
{
	__u8 i;

	if (strlen(membername) > 0)
		snprintf(val->name, sizeof(val->name), "%s->%s",
			 argname, membername);
	else
		strncpy(val->name, argname, sizeof(val->name));

	for (i = 0; i < MAX_TRACES; i++) {
		if (strcmp(argname, func->args[i].name) != 0)
			continue;
		p_debug("setting base arg for val %s to %d", val->name, i);
		val->base_arg = i;

		if (strlen(membername) > 0) {
			if (member_to_value(btf, membername,
					    func->args[i].type_id, val, 0))
				return -ENOENT;
		} else {
			val->type_id = func->args[i].type_id;
			val->flags |= func->args[i].flags;
			val->size = func->args[i].size;
		}
		return predicate_to_value(predicate, val);
	}
	p_err("Could not find '%s' in arguments/return value for '%s'",
	      argname, func->name);
	return -ENOENT;
}

static struct btf *get_btf(const char *name)
{
	struct btf *mod_btf;
	int err;

	p_debug("getting BTF for %s",
		name && strlen(name) > 0 ? name : "vmlinux");

	if (!vmlinux_btf) {
		vmlinux_btf = btf__load_vmlinux_btf();
		if (!vmlinux_btf) {
			err = -errno;
			p_err("No BTF, cannot determine type info: %s", strerror(-err));
			return NULL;
		}
	}
	if (!name || strlen(name) == 0)
		return vmlinux_btf;

	mod_btf = btf__load_module_btf(name, vmlinux_btf);
	if (!mod_btf) {
		err = -errno;
		p_err("No BTF for module '%s': %s", name, strerror(-err));
		return NULL;
	}
	return mod_btf;
}

static void copy_without_spaces(char *target, char *src)
{
	for (; *src != '\0'; src++)
		if (!isspace(*src))
			*(target++) = *src;
	*target = '\0';
}

static char *type_id_to_str(struct btf *btf, __s32 type_id, char *str)
{
	const struct btf_type *type;
	const char *name = "";
	char *prefix = "";
	char *suffix = " ";
	char *ptr = "";

	str[0] = '\0';

	switch (type_id) {
	case 0:
		name = "void";
		break;
	case KSNOOP_ID_UNKNOWN:
		name = "?";
		break;
	default:
		do {
			type = btf__type_by_id(btf, type_id);
			if (!type) {
				name = "?";
				break;
			}

			switch (BTF_INFO_KIND(type->info)) {
			case BTF_KIND_CONST:
			case BTF_KIND_VOLATILE:
			case BTF_KIND_RESTRICT:
				type_id = type->type;
				break;
			case BTF_KIND_PTR:
				ptr = "* ";
				type_id = type->type;
				break;
			case BTF_KIND_ARRAY:
				suffix = "[]";
				type_id = type->type;
				break;
			case BTF_KIND_STRUCT:
				prefix = "struct ";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_UNION:
				prefix = "union ";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_ENUM:
				prefix = "enum ";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_TYPEDEF:
				name = btf__str_by_offset(btf, type->name_off);
				break;
			default:
				name = btf__str_by_offset(btf, type->name_off);
				break;
			}
		} while (type_id >= 0 && strlen(name) == 0);
		break;
	}
	snprintf(str, MAX_STR, "%s%s%s%s", prefix, name, suffix, ptr);

	return str;
}

static char *value_to_str(struct btf *btf, struct value *val, char *str)
{

	str = type_id_to_str(btf, val->type_id, str);
	if (val->flags & KSNOOP_F_PTR)
		strncat(str, "*", MAX_STR);
	if (strlen(val->name) > 0 &&
	    strcmp(val->name, KSNOOP_RETURN_NAME) != 0)
		strncat(str, val->name, MAX_STR);

	return str;
}

/* based heavily on bpf_object__read_kallsyms_file() in libbpf.c */
static int get_func_ip_mod(struct func *func)
{
	char sym_type, sym_name[MAX_STR], mod_info[MAX_STR];
	unsigned long long sym_addr;
	int ret, err = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		err = errno;
		p_err("failed to open /proc/kallsyms: %s", strerror(err));
		return err;
	}

	while (true) {
		ret = fscanf(f, "%llx %c %128s%[^\n]\n",
			     &sym_addr, &sym_type, sym_name, mod_info);
		if (ret == EOF && feof(f))
			break;
		if (ret < 3) {
			p_err("failed to read kallsyms entry: %d", ret);
			err = -EINVAL;
			goto out;
		}
		if (strcmp(func->name, sym_name) != 0)
			continue;
		func->ip = sym_addr;
		func->mod[0] = '\0';
		/* get module name from [modname] */
		if (ret == 4) {
			if (sscanf(mod_info, "%*[\t ][%[^]]", func->mod) < 1) {
				p_err("failed to read module name");
				err = -EINVAL;
				goto out;
			}
		}
		p_debug("%s =  <ip %llx, mod %s>", func->name, func->ip,
			strlen(func->mod) > 0 ? func->mod : "vmlinux");
		break;
	}
out:
	fclose(f);
	return err;
}

static void trace_printf(void *ctx, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

#define VALID_NAME	"%[A-Za-z0-9\\-_]"
#define ARGDATA		"%[^)]"

static int parse_trace(char *str, struct trace *trace)
{
	__u8 i, nr_predicates = 0, nr_entry = 0, nr_return = 0;
	char argname[MAX_NAME], membername[MAX_NAME];
	char tracestr[MAX_STR], argdata[MAX_STR];
	struct func *func = &trace->func;
	char *arg, *saveptr;
	int ret;

	copy_without_spaces(tracestr, str);

	p_debug("Parsing trace '%s'", tracestr);

	trace->filter_pid = (__u32)filter_pid;
	if (filter_pid)
		p_debug("Using pid %lu as filter", trace->filter_pid);

	trace->btf = vmlinux_btf;

	ret = sscanf(tracestr, VALID_NAME "(" ARGDATA ")", func->name, argdata);
	if (ret <= 0)
		usage();
	if (ret == 1) {
		if (strlen(tracestr) > strlen(func->name)) {
			p_err("Invalid function specification '%s'", tracestr);
			usage();
		}
		argdata[0] = '\0';
		p_debug("got func '%s'", func->name);
	} else {
		if (strlen(tracestr) >
		    strlen(func->name) + strlen(argdata) + 2) {
			p_err("Invalid function specification '%s'", tracestr);
			usage();
		}
		p_debug("got func '%s', args '%s'", func->name, argdata);
		trace->flags |= KSNOOP_F_CUSTOM;
	}

	ret = get_func_ip_mod(func);
	if (ret) {
		p_err("could not get address of '%s'", func->name);
		return ret;
	}
	trace->btf = get_btf(func->mod);
	if (!trace->btf) {
		ret = -errno;
		p_err("could not get BTF for '%s': %s",
		      strlen(func->mod) ? func->mod : "vmlinux",
		      strerror(-ret));
		return -ENOENT;
	}
	trace->dump = btf_dump__new(trace->btf, trace_printf, NULL, NULL);
	if (!trace->dump) {
		ret = -errno;
		p_err("could not create BTF dump : %s", strerror(-ret));
		return -EINVAL;
	}

	ret = get_func_btf(trace->btf, func);
	if (ret) {
		p_debug("unexpected return value '%d' getting function", ret);
		return ret;
	}

	for (arg = strtok_r(argdata, ",", &saveptr), i = 0;
	     arg;
	     arg = strtok_r(NULL, ",", &saveptr), i++) {
		char *predicate = NULL;

		ret = sscanf(arg, VALID_NAME "->" VALID_NAME,
			     argname, membername);
		if (ret == 2) {
			if (strlen(arg) >
			    strlen(argname) + strlen(membername) + 2) {
				predicate = arg + strlen(argname) +
					    strlen(membername) + 2;
			}
			p_debug("'%s' dereferences '%s', predicate '%s'",
				argname, membername, predicate);
		} else {
			if (strlen(arg) > strlen(argname))
				predicate = arg + strlen(argname);
			p_debug("'%s' arg, predcate '%s'", argname, predicate);
			membername[0] = '\0';
		}

		if (i >= MAX_TRACES) {
			p_err("Too many arguments; up to %d are supported",
			      MAX_TRACES);
			return -EINVAL;
		}
		if (trace_to_value(trace->btf, func, argname, membername,
				   predicate, &trace->traces[i]))
			return -EINVAL;

		if (predicate)
			nr_predicates++;
		if (trace->traces[i].base_arg == KSNOOP_RETURN)
			nr_return++;
		else
			nr_entry++;
		trace->nr_traces++;
	}

	if (trace->nr_traces > 0) {
		trace->flags |= KSNOOP_F_CUSTOM;
		p_debug("custom trace with %d args", trace->nr_traces);

		/* If we have one or more predicates _and_ references to
		 * entry and return values, we need to activate "stash"
		 * mode where arg traces are stored on entry and not
		 * sent until return to ensure predicates are satisfied.
		 */
		if (nr_predicates > 0 && nr_entry > 0 && nr_return > 0) {
			trace->flags |= KSNOOP_F_STASH;
			p_debug("activating stash mode on entry");
		}
	} else {
		p_debug("Standard trace, function with %d arguments",
			func->nr_args);
		/* copy function arg/return value to trace specification. */
		memcpy(trace->traces, func->args, sizeof(trace->traces));
		for (i = 0; i < MAX_TRACES; i++)
			trace->traces[i].base_arg = i;
		trace->nr_traces = MAX_TRACES;
	}

	return 0;
}

static int parse_traces(int argc, char **argv, struct trace **traces)
{
	__u8 i;

	if (argc == 0)
		usage();

	if (argc > MAX_FUNC_TRACES) {
		p_err("A maximum of %d traces are supported", MAX_FUNC_TRACES);
		return -EINVAL;
	}
	*traces = calloc(argc, sizeof(struct trace));
	if (!*traces) {
		p_err("Could not allocate %d traces", argc);
		return -ENOMEM;
	}
	for (i = 0; i < argc; i++) {
		if (parse_trace(argv[i], &((*traces)[i])))
			return -EINVAL;
		if (!stack_mode || i == 0)
			continue;
		/* tell stack mode trace which function to expect next */
		(*traces)[i].prev_ip = (*traces)[i-1].func.ip;
		(*traces)[i-1].next_ip = (*traces)[i].func.ip;
	}
	return i;
}

static int cmd_info(int argc, char **argv)
{
	struct trace *traces = NULL;
	char str[MAX_STR];
	int nr_traces;
	__u8 i, j;

	nr_traces = parse_traces(argc, argv, &traces);
	if (nr_traces < 0)
		return nr_traces;

	for (i = 0; i < nr_traces; i++) {
		struct func *func = &traces[i].func;

		printf("%s%s(",
		       value_to_str(traces[i].btf, &func->args[KSNOOP_RETURN],
				    str),
		       func->name);
		for (j = 0; j < func->nr_args; j++) {
			if (j > 0)
				printf(", ");
			printf("%s", value_to_str(traces[i].btf, &func->args[j],
						  str));
		}
		if (func->nr_args > MAX_ARGS)
			printf(" /* and %d more args that are not traceable */",
			       func->nr_args - MAX_ARGS);
		printf(");\n");
	}
	free(traces);
	return 0;
}

static void trace_handler(void *ctx, int cpu, void *data, __u32 size)
{
	struct trace *trace = data;
	int i, shown, ret;

	p_debug("got trace, size %d", size);
	if (size < (sizeof(*trace) - MAX_TRACE_BUF)) {
		p_err("\t/* trace buffer size '%u' < min %ld */",
			size, sizeof(trace) - MAX_TRACE_BUF);
		return;
	}
	printf("%16lld %4d %8u %s(\n", trace->time, trace->cpu, trace->pid,
	       trace->func.name);

	for (i = 0, shown = 0; i < trace->nr_traces; i++) {
		DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts);
		bool entry = trace->data_flags & KSNOOP_F_ENTRY;
		struct value *val = &trace->traces[i];
		struct trace_data *data = &trace->trace_data[i];

		opts.indent_level = 36;
		opts.indent_str = " ";

		/* skip if it's entry data and trace data is for return, or
		 * if it's return and trace data is entry; only exception in
		 * the latter case is if we stashed data; in such cases we
		 * want to see it as it's a mix of entry/return data with
		 * predicates.
 		 */
		if ((entry && !base_arg_is_entry(val->base_arg)) ||
		    (!entry && base_arg_is_entry(val->base_arg) &&
		     !(trace->flags & KSNOOP_F_STASH)))
			continue;

		if (val->type_id == 0)
			continue;

		if (shown > 0)
			printf(",\n");
		printf("%34s %s = ", "", val->name);
		if (val->flags & KSNOOP_F_PTR)
			printf("*(0x%llx)", data->raw_value);
		printf("\n");

		if (data->err_type_id != 0) {
			char typestr[MAX_STR];

			printf("%36s /* Cannot show '%s' as '%s%s'; invalid/userspace ptr? */\n",
			       "",
			       val->name,
			       type_id_to_str(trace->btf,
					      val->type_id,
					      typestr),
			       val->flags & KSNOOP_F_PTR ?
			       " *" : "");
		} else {
			ret = btf_dump__dump_type_data
				(trace->dump, val->type_id,
				 trace->buf + data->buf_offset,
				 data->buf_len, &opts);
			/* truncated? */
			if (ret == -E2BIG)
				printf("%36s... /* %d bytes of %d */", "",
				       data->buf_len,
				       val->size);
		}
		shown++;

	}
	printf("\n%31s);\n\n", "");
	fflush(stdout);
}

static void lost_handler(void *ctx, int cpu, __u64 cnt)
{
	p_err("\t/* lost %llu events */", cnt);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int add_traces(struct bpf_map *func_map, struct trace *traces,
		      int nr_traces)
{
	int i, j, ret, nr_cpus = libbpf_num_possible_cpus();
	struct trace *map_traces;

	map_traces = calloc(nr_cpus, sizeof(struct trace));
	if (!map_traces) {
		p_err("Could not allocate memory for %d traces", nr_traces);
		return -ENOMEM;
	}
	for (i = 0; i < nr_traces; i++) {
		for (j = 0; j < nr_cpus; j++)
			memcpy(&map_traces[j], &traces[i],
			       sizeof(map_traces[j]));

		ret = bpf_map_update_elem(bpf_map__fd(func_map),
					  &traces[i].func.ip,
					  map_traces,
					  BPF_NOEXIST);
		if (ret) {
			p_err("Could not add map entry for '%s': %s",
			      traces[i].func.name, strerror(-ret));
			break;
		}
	}
	free(map_traces);
	return ret;
}

static int attach_traces(struct ksnoop_bpf *skel, struct trace *traces,
			 int nr_traces)
{
	int i, ret;

	for (i = 0; i < nr_traces; i++) {
		traces[i].links[0] =
			bpf_program__attach_kprobe(skel->progs.kprobe_entry,
						   false,
						   traces[i].func.name);
		if (!traces[i].links[0]) {
			ret = -errno;
			p_err("Could not attach kprobe to '%s': %s",
			      traces[i].func.name, strerror(-ret));
				return ret;
		}
		p_debug("Attached kprobe for '%s'", traces[i].func.name);

		traces[i].links[1] =
			bpf_program__attach_kprobe(skel->progs.kprobe_return,
						   true,
						   traces[i].func.name);
		if (!traces[i].links[1]) {
			ret = -errno;
			p_err("Could not attach kretprobe to '%s': %s",
			      traces[i].func.name, strerror(-ret));
			return ret;
		}
		p_debug("Attached kretprobe for '%s'", traces[i].func.name);
	}
	return 0;
}

static int cmd_trace(int argc, char **argv)
{
	struct bpf_map *perf_map, *func_map;
	struct perf_buffer *pb = NULL;
	struct ksnoop_bpf *skel;
	int i, nr_traces, ret = -1;
	struct trace *traces = NULL;

	nr_traces = parse_traces(argc, argv, &traces);
	if (nr_traces < 0)
		return nr_traces;

	skel = ksnoop_bpf__open_and_load();
	if (!skel) {
		ret = -errno;
		p_err("Could not load ksnoop BPF: %s", strerror(-ret));
		return 1;
	}

	perf_map = skel->maps.ksnoop_perf_map;
	if (!perf_map) {
		p_err("Could not find '%s'", "ksnoop_perf_map");
		goto cleanup;
	}
	func_map = bpf_object__find_map_by_name(skel->obj, "ksnoop_func_map");
	if (!func_map) {
		p_err("Could not find '%s'", "ksnoop_func_map");
		goto cleanup;
	}

	if (add_traces(func_map, traces, nr_traces)) {
		p_err("Could not add traces to '%s'", "ksnoop_func_map");
		goto cleanup;
	}

	if (attach_traces(skel, traces, nr_traces)) {
		p_err("Could not attach %d traces", nr_traces);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(perf_map), pages,
			      trace_handler, lost_handler, NULL, NULL);
	if (!pb) {
		ret = -errno;
		p_err("Could not create perf buffer: %s", strerror(-ret));
		goto cleanup;
	}

	printf("%16s %4s %8s %s\n", "TIME", "CPU", "PID", "FUNCTION/ARGS");

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		ret = 1;
		goto cleanup;
	}

	while (!exiting) {
		ret = perf_buffer__poll(pb, 1);
		if (ret < 0 && ret != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-ret));
			goto cleanup;
		}
		/* reset ret to return 0 if exiting */
		ret = 0;
	}

cleanup:
	for (i = 0; i < nr_traces; i++) {
		bpf_link__destroy(traces[i].links[0]);
		bpf_link__destroy(traces[i].links[1]);
	}
	free(traces);
	perf_buffer__free(pb);
	ksnoop_bpf__destroy(skel);

	return ret;
}

struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
};

struct cmd cmds[] = {
	{ "info",	cmd_info },
	{ "trace",	cmd_trace },
	{ "help",	cmd_help },
	{ NULL,		NULL }
};

static int cmd_select(int argc, char **argv)
{
	int i;

	for (i = 0; cmds[i].cmd; i++) {
		if (strncmp(*argv, cmds[i].cmd, strlen(*argv)) == 0)
			return cmds[i].func(argc - 1, argv + 1);
	}
	return cmd_trace(argc, argv);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "debug",	no_argument,		NULL,	'd' },
		{ "verbose",	no_argument,		NULL,	'v' },
		{ "help",	no_argument,		NULL,	'h' },
		{ "version",	no_argument,		NULL,	'V' },
		{ "pages",	required_argument,	NULL,	'P' },
		{ "pid",	required_argument,	NULL,	'p' },
		{ 0 }
	};
	int opt;

	bin_name = argv[0];

	while ((opt = getopt_long(argc, argv, "dvhp:P:sV", options,
				  NULL)) >= 0) {
		switch (opt) {
		case 'd':
			verbose = true;
			log_level = DEBUG;
			break;
		case 'v':
			verbose = true;
			log_level = DEBUG;
			break;
		case 'h':
			return cmd_help(argc, argv);
		case 'V':
			return do_version(argc, argv);
		case 'p':
			filter_pid = atoi(optarg);
			break;
		case 'P':
			pages = atoi(optarg);
			break;
		case 's':
			stack_mode = true;
			break;
		default:
			p_err("unrecognized option '%s'", argv[optind - 1]);
			usage();
		}
	}
	if (argc == 1)
		usage();
	argc -= optind;
	argv += optind;
	if (argc < 0)
		usage();

	libbpf_set_print(libbpf_print_fn);

	return cmd_select(argc, argv);
}
