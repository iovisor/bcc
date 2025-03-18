// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 Samsung */
#include <argp.h>
#include <json-c/json_object.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <math.h>
#include <bpf/bpf.h>
#include "blkalgn.h"
#include "blkalgn.skel.h"
#include "blkalgn.h"
#include "blk_types.h"
#include <string.h>
#include "trace_helpers.h"
#include <json-c/json.h>
#include <stdlib.h>

#include "blazesym.h"

static blazesym *symbolizer;

static struct env {
	bool verbose;
	char *disk;
	char *ops;
	char *json;
	bool trace;
	unsigned int len;
	unsigned int align;
	char *comm;
	int comm_len;
	bool stacktrace;
} env;

const char *argp_program_version = "blkalgn 0.2";
const char *argp_program_bug_address = "Daniel Gomez <da.gomez@samsung.com>";
const char argp_program_doc[] =
	"BPF blkalgn application.\n"
	"\n"
	"It traces block I/O operations and reports I/O granularity and\n"
	"alignment.\n"
	"\n"
	"USAGE: ./blkalgn [-d <disk>] [-o <ops>] [-j <output>] [-t] [-v]\n";

static volatile bool exiting = false;
static struct partitions *partitions;

struct map_fd_ctx {
	int halign;
	int hgran;
};

static const char *ops[] = {
	[REQ_OP_READ] = "Read",
	[REQ_OP_WRITE] = "Write",
	[REQ_OP_FLUSH] = "Flush",
	[REQ_OP_DISCARD] = "Discard",
	[REQ_OP_SECURE_ERASE] = "SecureErase",
	[REQ_OP_ZONE_RESET] = "ZoneReset",
	[REQ_OP_WRITE_SAME] = "WriteSame",
	[REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll",
	[REQ_OP_WRITE_ZEROES] = "WriteZeroes",
	[REQ_OP_ZONE_OPEN] = "ZoneOpen",
	[REQ_OP_ZONE_CLOSE] = "ZoneClose",
	[REQ_OP_ZONE_FINISH] = "ZoneFinish",
	[REQ_OP_SCSI_IN] = "SCSIIn",
	[REQ_OP_SCSI_OUT] = "SCSIOut",
	[REQ_OP_DRV_IN] = "DrvIn",
	[REQ_OP_DRV_OUT] = "DrvOut",
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

/*
 * From linux/blk-mq.h:
 *
 * The basic unit of block I/O is a sector. It is used in a number of contexts
 * in Linux (blk, bio, genhd). The size of one sector is 512 = 2**9
 * bytes. Variables of type sector_t represent an offset or size that is a
 * multiple of 512 bytes. Hence these two constants.
 */
#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "disk", 'd', "DISK", 0, "Trace this disk only", 0 },
	{ "ops", 'o', "OPS", 0, "Trace this ops only", 0 },
	{ "json", 'j', "JSON", 0, "Output to JSON", 0 },
	{ "trace", 't', NULL, 0, "Enable trace output", 0 },
	{ "length", 'l', "LENGTH", 0, "Trace this length only", 0 },
	{ "alignment", 'a', "ALIGNMENT", 0, "Trace this alignment only", 0 },
	{ "comm", 'c', "COMM", 0, "Trace this comm only", 0 },
	{ "stacktrace", 's', NULL, 0, "Enable stack trace output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static int get_rq_op(const char *value)
{
	for (int i = 0; i < ARRAY_SIZE(ops); i++) {
		if (ops[i] && strcmp(ops[i], value) == 0) {
			return i;
		}
	}
	return -1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > NAME_LEN) {
			fprintf(stderr, "disk name too long\n");
			argp_usage(state);
		}
		break;
	case 'o':
		env.ops = arg;
		if (strlen(arg) + 1 > NAME_LEN) {
			fprintf(stderr, "op name too long\n");
			argp_usage(state);
		}
		break;
	case 'j':
		env.json = arg;
		if (strlen(arg) + 1 > MAX_FILENAME_LEN) {
			fprintf(stderr, "json name too long\n");
			argp_usage(state);
		}
		break;
	case 't':
		env.trace = true;
		break;
	case 'l':
		errno = 0;
		env.len = strtol(arg, NULL, 10);
		if (errno || env.len <= 0) {
			fprintf(stderr, "Invalid length value: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'a':
		errno = 0;
		env.align = strtol(arg, NULL, 10);
		if (errno || env.align <= 0) {
			fprintf(stderr, "Invalid alignment value: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.comm = arg;
		env.comm_len = (strlen(arg) + 1) > TASK_COMM_LEN ?
				       TASK_COMM_LEN :
				       (strlen(arg) + 1);
		break;
	case 's':
		env.stacktrace = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int check_ops(int x)
{
	if (x >= 0 && x < ARRAY_SIZE(ops) && ops[x])
		return 1;
	return 0;
}

static inline bool is_lba_aligned(__u32 len, __u32 algn_len, __u64 lba,
				  __u32 algn_lba)
{
	return !(len % algn_len) && !(lba % algn_lba);
}

bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

static inline __u32 align(const struct event *e)
{
	__u16 lbs = 512;
	__u64 lba = e->sector;
	__u32 align_len = e->len;
	__u32 align_lba = align_len / lbs;
	__u32 alignment = lbs;

	if (is_power_of_2(e->len) &&
	    is_lba_aligned(e->len, align_len, lba, align_lba))
		return e->len;

	align_len = lbs << 1UL;
	align_lba = align_len / lbs;

	while (align_len < e->len) {
		if (!is_lba_aligned(e->len, align_len, lba, align_lba))
			break;

		alignment = align_len;
		align_len = align_len << 1UL;
		align_lba = align_len / lbs;
	}

	return alignment;
}

void _json_object_init(json_object *jroot, const char *key,
		       json_object **jobject)
{
	if (!json_object_object_get_ex(jroot, key, jobject)) {
		*jobject = json_object_new_object();
		json_object_object_add(jroot, key, *jobject);
	}
}

static void _json_object_add_hval(json_object *jobj, struct hval *hist)
{
	char s[12];

	for (int i = 0; i < MAX_SLOTS; i++) {
		if (hist->slots[i]) {
			/* Generate output in bytes */
			if (hist->granularity)
				snprintf(s, sizeof(s), "%u",
					 (i) << hist->granularity);
			else
				snprintf(s, sizeof(s), "%u", 1 << i);
			json_object_object_add(
				jobj, s, json_object_new_int64(hist->slots[i]));
		}
	}
}

/*
 * Add disks -> partition (e.g. nvme0n1) -> { granularity, alignment }.
 * Granularity:
 * - "key": Block in steps of 512 bytes (block << 9).
 * - value: Counter.
 * Alignment:
 * - "key": Block in power of 2 (block << 12).
 * - value: Counter.
 *
 * Example:
 * {
 *  "disks":{
 *    "vda":{
 *      "granularity":{
 *        "0":2,
 *        "8":27,
 *        "16":3,
 *        "24":3,
 *        "32":1,
 *        "48":1,
 *        "64":1,
 *        "96":1,
 *        "128":1,
 *        "864":1,
 *        "2032":1
 *      },
 *      "alignment":{
 *        "9":2,
 *        "12":37,
 *        "13":2,
 *        "14":1
 *      }
 *    }
 *  }
 * }
 */
static int hash_to_json(int fd, json_object *jroot, const char *key)
{
	struct hkey lookup_key = {}, next_key;
	struct hval val;
	int err;

	json_object *jdisks;
	_json_object_init(jroot, "disks", &jdisks);

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &val);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}

		json_object *jdisk;
		_json_object_init(jdisks, next_key.disk, &jdisk);

		json_object *jobj;
		_json_object_init(jdisk, key, &jobj);

		_json_object_add_hval(jobj, &val);

		lookup_key = next_key;
	}

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return 1;
		}
		lookup_key = next_key;
	}

	return 0;
}

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void print_linear_hist_bytes(unsigned int *vals, int vals_size,
			     unsigned int base, unsigned int step,
			     const char *val_type, unsigned int gran)
{
	int i, stars_max = 40, idx_min = -1, idx_max = -1;
	unsigned int val, val_max = 0;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0) {
			idx_max = i;
			if (idx_min < 0)
				idx_min = i;
		}
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("     %-13s : count    distribution\n", val_type);
	for (i = idx_min; i <= idx_max; i++) {
		val = vals[i];
		if (!val)
			continue;
		printf("        %-10d : %-8d |", ((base + i * step)) << gran,
		       val);
		print_stars(val, val_max, stars_max);
		printf("|\n");
	}
}

void print_histograms(struct map_fd_ctx *fd)
{
	struct hkey hg_key = {}, ha_key = {};
	struct hval hg_value, ha_value;
	__u64 count = 0;

	while (bpf_map_get_next_key(fd->hgran, &hg_key, &hg_key) == 0) {
		if (bpf_map_lookup_elem(fd->hgran, &hg_key, &hg_value) == 0) {
			printf("\nI/O Granularity Histogram for Device %s "
			       "(lbads: %d - %lu bytes)\n",
			       hg_key.disk, hg_value.granularity,
			       1UL << hg_value.granularity);
			for (int i = 0; i < MAX_SLOTS; i++)
				if (hg_value.slots[i])
					count += hg_value.slots[i];

			printf("Total I/Os: %llu\n", count);
			print_linear_hist_bytes(hg_value.slots, MAX_SLOTS, 0, 1,
						"Bytes", hg_value.granularity);
		}
	}

	while (bpf_map_get_next_key(fd->halign, &ha_key, &ha_key) == 0) {
		if (bpf_map_lookup_elem(fd->halign, &ha_key, &ha_value) == 0) {
			printf("\nI/O Alignment Histogram for Device %s\n",
			       ha_key.disk);
			print_log2_hist(ha_value.slots, MAX_SLOTS, "Bytes");
		}
	}
}

void print_json(struct map_fd_ctx *fd)
{
	json_object *jroot = json_object_new_object();
	FILE *fp;

	hash_to_json(fd->hgran, jroot, "granularity");
	hash_to_json(fd->halign, jroot, "alignment");

	fp = fopen(env.json, "w");
	if (!fp) {
		fprintf(stderr, "failed to open file: %s\n", env.json);
		return;
	}
	fprintf(fp, "%s\n",
		json_object_to_json_string_ext(jroot, JSON_C_TO_STRING_PRETTY));
	fclose(fp);
}

int _bpf_map_increase_slot(int fd, struct hkey key, struct hval val, __u32 slot,
			   __u32 gran, const struct event *e)
{
	strncpy(key.disk, e->disk, NAME_LEN);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	if (!bpf_map_lookup_elem(fd, &key, &val))
		val.slots[slot] += 1;
	else
		val.slots[slot] = 1;

	val.granularity = gran;

	if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
		fprintf(stderr, "failed to update map\n");
		return 1;
	}

	return 0;
}

static void show_stack_trace(const __u64 *stack, int stack_sz, pid_t pid)
{
	const struct blazesym_result *result;
	const struct blazesym_csym *sym;
	sym_src_cfg src;
	int i, j;

	if (pid) {
		src.src_type = SRC_T_PROCESS;
		src.params.process.pid = pid;
	} else {
		src.src_type = SRC_T_KERNEL;
		src.params.kernel.kallsyms = NULL;
		src.params.kernel.kernel_image = NULL;
	}

	result = blazesym_symbolize(symbolizer, &src, 1,
				    (const uint64_t *)stack, stack_sz);

	for (i = 0; i < stack_sz; i++) {
		if (!result || result->size <= i || !result->entries[i].size) {
			printf("  %d [<%016llx>]\n", i, stack[i]);
			continue;
		}

		if (result->entries[i].size == 1) {
			sym = &result->entries[i].syms[0];
			if (sym->path && sym->path[0]) {
				printf("  %d [<%016llx>] %s+0x%llx %s:%ld\n", i,
				       stack[i], sym->symbol,
				       stack[i] - sym->start_address, sym->path,
				       sym->line_no);
			} else {
				printf("  %d [<%016llx>] %s+0x%llx\n", i,
				       stack[i], sym->symbol,
				       stack[i] - sym->start_address);
			}
			continue;
		}

		printf("  %d [<%016llx>]\n", i, stack[i]);
		for (j = 0; j < result->entries[i].size; j++) {
			sym = &result->entries[i].syms[j];
			if (sym->path && sym->path[0]) {
				printf("        %s+0x%llx %s:%ld\n",
				       sym->symbol,
				       stack[i] - sym->start_address, sym->path,
				       sym->line_no);
			} else {
				printf("        %s+0x%llx\n", sym->symbol,
				       stack[i] - sym->start_address);
			}
		}
	}

	blazesym_result_free(result);
}

static void print_stack_trace(const struct event *e)
{
	if (e->kstack_sz <= 0 && e->ustack_sz <= 0)
		printf("No stack\n");

	if (e->kstack_sz > 0) {
		printf("Kernel:\n");
		show_stack_trace(e->kstack, e->kstack_sz / sizeof(__u64), 0);
	} else {
		printf("No Kernel Stack\n");
	}

	if (e->ustack_sz > 0) {
		printf("Userspace:\n");
		show_stack_trace(e->ustack, e->ustack_sz / sizeof(__u64),
				 e->pid);
	} else {
		printf("No Userspace Stack\n");
	}

	printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct map_fd_ctx *fd = (struct map_fd_ctx *)ctx;
	struct hkey hg_key, ha_key;
	struct hval hg_value = {}, ha_value = {};
	__u32 algn = align(e);
	__u64 lba = e->sector << SECTOR_SHIFT;
	__u64 lbs_shift = log2(e->lbs);
	int err;

	if (env.align && env.align != algn)
		return 0;

	err = _bpf_map_increase_slot(fd->hgran, hg_key, hg_value,
				     e->len >> lbs_shift, lbs_shift, e);
	if (err)
		return err;

	err = _bpf_map_increase_slot(fd->halign, ha_key, ha_value, log2l(algn),
				     0, e);
	if (err)
		return err;

	if (!env.trace)
		return 0;

	if (check_ops(e->flags & REQ_OP_MASK))
		printf("%-10s 0x%-8x %-8s %-10d %-21llu %-10d %-16s %-8d\n",
		       e->disk, e->flags, ops[e->flags & REQ_OP_MASK], e->len,
		       lba, e->pid, e->comm, algn);
	else
		printf("%-10s 0x%-8x %-8d %-10d %-21llu %-10d %-16s %-8d\n",
		       e->disk, e->flags, e->flags & REQ_OP_MASK, e->len, lba,
		       e->pid, e->comm, algn);

	if (env.stacktrace)
		print_stack_trace(e);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct blkalgn_bpf *obj;
	const struct partition *partition;
	int op = -1, err;
	struct map_fd_ctx fd;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	obj = blkalgn_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and load BPF object\n");
		return 1;
	}

	partitions = partitions__load();
	if (!partitions) {
		fprintf(stderr, "failed to load partitions info\n");
		goto cleanup;
	}

	if (env.disk) {
		partition = partitions__get_by_name(partitions, env.disk);
		if (!partition) {
			fprintf(stderr, "partition name does not exist\n");
			goto cleanup;
		}
		obj->rodata->filter_dev = true;
		obj->rodata->targ_dev = partition->dev;
	}

	if (env.ops) {
		op = get_rq_op(env.ops);
		if (op < 0) {
			fprintf(stderr, "op name not found\n");
			goto cleanup;
		}
		obj->rodata->filter_ops = true;
		obj->rodata->targ_ops = op;
	}

	if (env.len) {
		obj->rodata->filter_len = true;
		obj->rodata->targ_len = env.len;
	}

	if (env.comm) {
		obj->rodata->filter_comm = true;
		strncpy((char *)obj->rodata->targ_comm, env.comm, env.comm_len);
	}

	if (env.stacktrace)
		obj->rodata->capture_stack = true;

	err = blkalgn_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load and verify BPF object\n");
		goto cleanup;
	}

	err = blkalgn_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF object\n");
		goto cleanup;
	}

	fd.halign = bpf_map__fd(obj->maps.halgn_map);
	fd.hgran = bpf_map__fd(obj->maps.hgran_map);

	symbolizer = blazesym_new();
	if (!symbolizer) {
		fprintf(stderr, "failed to load blazesym\n");
		err = -ENOMEM;
		goto cleanup;
	}

	printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

	rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), handle_event, &fd,
			      NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	if (env.trace)
		printf("%-10s %-10s %-8s %-10s %-21s %-10s %-16s %-8s\n",
		       "DISK", "OPS", "FLAGS", "LEN", "LBA", "PID", "COMM",
		       "ALGN");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "error polling ring buffer: %d\n", err);
			break;
		}
	}

	printf("\n");
	print_histograms(&fd);
	if (env.json)
		print_json(&fd);

cleanup:
	blazesym_free(symbolizer);
	ring_buffer__free(rb);
	partitions__free(partitions);
	blkalgn_bpf__destroy(obj);

	return err < 0 ? -err : 0;
}
