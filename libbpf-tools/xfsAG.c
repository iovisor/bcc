// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2025 Samsung Electronics Co., Ltd.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <xfs/xfs.h>
#include <xfs/xfs_format.h>
#include <bpf/bpf.h>
#include "xfsAG.skel.h"
#include "trace_helpers.h"
#include "xfsAG.h"



bool exiting;

struct config {
	char* dir;
	char* dev;
	time_t interval;
	int times;
};

void print_usage(FILE* fp, int argc, char** argv) {
	fprintf(fp,
		"Count read/write/update number of every AG in an XFS SSD.\n"
		"\n"
		"Usage: %s [-h, --help] [-d <dir>, --dir==<dir>] [interval] [count]\n"
		"\n"
		"Options:\n"
		"  -d, --dir=<dir>              Trace the specific device\n"
		"  -h, --help                   Show this help\n"
		"  interval                     Specify the amount of time in seconds between each report\n"
		"  count                        Limit the number of reports (default: unlimited)\n"
		"\n"
		"Examples:\n"
		"  %s -d /mnt/xfs               # Trace the device mounted on '/mnt/xfs'\n"
		"  %s -d /mnt/xfs 1 10          # Print 10 reports at 1 second intervals\n",
		argv[0], argv[0], argv[0]);
}

int parse_opt(struct config* config, int argc, char** argv) {
	int c;
	int option_index = 0;
	static struct option long_options[] = {
		{"dir", required_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "d:h", long_options, &option_index)) != -1) {
		switch (c) {
		case 'd':
			config->dir = optarg;
			break;
		case 'h':
			print_usage(stdout, argc, argv);
			exit(0);
		case '?':
			print_usage(stderr, argc, argv);
			exit(1);
		default:
			print_usage(stderr, argc, argv);
			exit(1);
		}
	}

	if (optind < argc) {
		if (optind + 1 > argc) {
			fprintf(stderr, "Missing value for interval\n");
			print_usage(stderr, argc, argv);
			exit(1);
		}
		config->interval = atoi(argv[optind++]);
		if (optind < argc) {
			config->times = atoi(argv[optind++]);
		}
	}

	return 0;
}

void my_print(FILE *fp, bool isenter, const char *format, ...){
	char buffer[100]={};
	va_list args;
	va_start(args, format);

	vsnprintf(buffer, sizeof(buffer), format, args);

	va_end(args);
	
	if(isenter){
		if(fp)
    		fprintf(fp, "%s\n", buffer);
		else
			printf("%s\n", buffer);
	}
	else{
		if(fp)
    		fprintf(fp, "%s", buffer);
		else
			printf("%s", buffer);
	}
	
}

void sig_handler(int sig)
{
	exiting = true;
}

int endian_convert_b_to_l(__u64 num, int lenth)
{
	if (lenth > 8)
		return -1;
	unsigned char *p = (unsigned char*) & num;
	__u64 res = 0;
	for(int i = 0; i < lenth; i++){
		int off = (lenth - 1 - i) * 8;
		__u64 it = (__u64)*(p + i);
		it = it << off;
		res += it;
	}
	return res;
}

void print_ag_infos(int fd_ag_infos, FILE* fp_ag, char* time, struct xfs_config* xfs_config)
{
	struct ag_infos ag_infos_val = {};

	my_print(fp_ag, true, "%s", time);
	my_print(fp_ag, false, "%-5s %-12s %-20s %-20s ",
		"agno", "ag_size(MB)", "direct_read_cnt", "buffer_write_cnt");
	my_print(fp_ag, true, "%-20s %-20s %-20s",
		"direct_write_cnt", "buffer_update_cnt", "direct_update_cnt");
	for(int key = 0; key < xfs_config->ag_count; key++){
		bool bre = true;
		if(bpf_map_lookup_elem(fd_ag_infos, &key, &ag_infos_val))
			continue;
		for (int i = 0; i < RWU_TYPE_CNT; i++) {
			if (ag_infos_val.rwu_cnt[i])
				bre = false;
		}
		if (bre)
			continue;
		my_print(fp_ag, false, "%-5d %-12lld %-20lld %-20lld ",
			key, ag_infos_val.ag_size,
			ag_infos_val.rwu_cnt[RWU_TYPE_DIRECT_READ], ag_infos_val.rwu_cnt[RWU_TYPE_BUFFER_WRITE]);
		my_print(fp_ag, true, "%-20lld %-20lld %-20lld",
			ag_infos_val.rwu_cnt[RWU_TYPE_DIRECT_WRITE], ag_infos_val.rwu_cnt[RWU_TYPE_BUFFER_UPDATE],
			ag_infos_val.rwu_cnt[RWU_TYPE_DIRECT_UPDATE]);
	}
}

int get_mounts_dev_by_dir(const char* dev, char* dir, char* type) {
	FILE* f = NULL;
	char mount_dev[256] = { 0 };
	char mount_dir[256] = { 0 };
	char mount_type[50] = { 0 };
	int match;

	if (dir[strlen(dir) - 1] == '/')
		dir[strlen(dir) - 1] = '\0';

	f = fopen("/proc/mounts", "r");
	if (!f) {
		fprintf(stderr, "could not open /proc/mounts\n");
		return -1;
	}

	do {
		match = fscanf(f, "%255s %255s %49s\n",
			mount_dev, mount_dir, mount_type);
		if (match == 3 && strcmp(dir, mount_dir) == 0) {
			memcpy((void*)dev, mount_dev, sizeof(mount_dev));
			memcpy(type, mount_type, sizeof(mount_type));
			fclose(f);
			return 0;
		}
		memset(mount_dev, 0, strlen(mount_dev));
		memset(mount_dir, 0, strlen(mount_dir));
		memset(mount_type, 0, strlen(mount_type));
	} while (match != EOF);

	fclose(f);
	return -1;
}

void initialize_map_ag_infos(int fd_ag_infos, struct xfs_config* xfs_config, __u64* ag_sizes)
{
	struct ag_infos ag_infos_val = {};

	for(int key = 0; key < xfs_config->ag_count; key++){
		ag_infos_val.ag_size = ag_sizes[key];
		if (bpf_map_update_elem(fd_ag_infos, &key, &ag_infos_val, BPF_ANY) != 0) {
			fprintf(stderr, "failed to init map\n");
			continue;
		}
	}
}

void xfs_info_get(struct xfs_config* xfs_config, struct config* config, __u64* ag_sizes)
{
	struct sysinfo info;
	time_t curtime;
	if (sysinfo(&info)) {
		fprintf(stderr, "Failed to get sysinfo, errno:%u, reason:%s\n", errno, strerror(errno));
	}
	time(&curtime);
	xfs_config->system_up = curtime - info.uptime;
	int fd_xfs_dev = open(config->dev, O_RDONLY);
	if (fd_xfs_dev < 0) {
		fprintf(stderr, "failed to open %s\n", config->dev);
		goto cleanup;
	}
	struct xfs_sb sb;
	if(pread(fd_xfs_dev, &sb, sizeof(sb), 0) != sizeof(sb)){
		fprintf(stderr, "failed to read super block of %s\n", config->dev);
		goto cleanup;
	}
	xfs_config->block_size = endian_convert_b_to_l(sb.sb_blocksize, sizeof(sb.sb_blocksize));
	xfs_config->sector_size = endian_convert_b_to_l(sb.sb_sectsize, sizeof(sb.sb_sectsize));
	xfs_config->inode_size = endian_convert_b_to_l(sb.sb_inodesize, sizeof(sb.sb_inodesize));
	xfs_config->ag_blocks = endian_convert_b_to_l(sb.sb_agblocks, sizeof(sb.sb_agblocks));
	xfs_config->data_blocks = endian_convert_b_to_l(sb.sb_dblocks, sizeof(sb.sb_dblocks));
	xfs_config->ag_count = endian_convert_b_to_l(sb.sb_agcount, sizeof(sb.sb_agcount));

	for(int i = 0; i < xfs_config->ag_count; i++){
		// AG Size info
		if(i == xfs_config->ag_count - 1)
			ag_sizes[i] = xfs_config->data_blocks % xfs_config->ag_blocks;
		else
			ag_sizes[i] = xfs_config->ag_blocks;
		ag_sizes[i] *= xfs_config->block_size;
		ag_sizes[i] /= 1024*1024;
	}

cleanup:
	if (fd_xfs_dev > 0)
		close(fd_xfs_dev);
}

void get_device_name_from_path(char *device_name, struct config* config)
{
	int len = strlen(config->dev);
	int pos;
	for (pos = len - 1; pos >= 0; pos--) {
		if (config->dev[pos] == '/') break;
	}
	pos = pos >= 0 ? pos + 1 : 0;
	memcpy(device_name, config->dev + pos, len - pos);
}

int program_configure(int argc, char** argv, FILE** fp_ag, struct config *config,
	struct partitions** partitions, const struct partition** partition)
{
	const char* fs_type = "xfs";
	const char* log_path = "ag_infos.log";
	char device_name[20];
	char mount_type[50];
	config->dev = malloc(256);
	memset(config->dev, 0, 256);

	if (parse_opt(config, argc, argv)) {
		fprintf(stderr, "error: parse_opt failed!\n");
		return -1;
	}

	if (!config->dir) {
		fprintf(stderr, "error: the FS mouned dir is needed\n");
		return -1;
	}

	// if the dev is mounted or made by xfs
	if (get_mounts_dev_by_dir(config->dev, config->dir, mount_type)) {
		fprintf(stderr, "error: failed to find %s\n", config->dir);
		return -1;
	}
	if (strcmp(fs_type, mount_type)) {
		fprintf(stderr, "error: the fs is not xfs\n");
		return -1;
	}

	// get the device_name(eg. get 'nvme0n1' from '/dev/nvme0n1')
	get_device_name_from_path(device_name, config);
	// get the dev num, which will be send to eBPF program
	*partitions = partitions__load();
	if (!*partitions) {
		fprintf(stderr, "error: failed to load partitions\n");
		return -1;
	}
	*partition = partitions__get_by_name(*partitions, device_name);
	if (!*partition) {
		fprintf(stderr, "error: failed to find the %s in partitions\n", device_name);
		return -1;
	}
	// output
	*fp_ag = fopen(log_path, "w");
	if (!*fp_ag) {
		fprintf(stderr, "error: failed to open %s\n", log_path);
		return -1;
	}

	/* INT EVENT */
	signal(SIGINT, sig_handler);

	return 0;
}

int bpf_initialize_and_load(struct xfsAG_bpf** objp, int* fd_ag_infos, struct config* config,
	__u64* ag_sizes, const struct partition* partition, struct xfs_config* xfs_config)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	/* bpf open */
	*objp = xfsAG_bpf__open_opts(&open_opts);
	if (!(*objp)) {
		fprintf(stderr, "error: failed to open BPF object\n");
		return -1;
	}

	/* bpf load */
	xfs_info_get(xfs_config, config, ag_sizes);
	(*objp)->rodata->ag_count = xfs_config->ag_count;
	(*objp)->rodata->device_num = partition->dev;

	if (xfsAG_bpf__load(*objp)) {
		fprintf(stderr, "failed to load BPF object\n");
		return -1;
	}

	/* bpf attach */
	if (xfsAG_bpf__attach(*objp)) {
		fprintf(stderr, "failed to attach BPF programs\n");
		return -1;
	}

	/* initialize the MAP map_ag_infos */
	*fd_ag_infos = bpf_map__fd((*objp)->maps.map_ag_infos);
	initialize_map_ag_infos(*fd_ag_infos, xfs_config, ag_sizes);

	return 0;
}

int main(int argc, char **argv)
{
	struct config config = {
	.times = 100000000,
	.interval = 100000000
	};
	struct partitions* partitions = NULL;
	const struct partition* partition = NULL;
	struct xfs_config xfs_config = {};
	char time_buffer[20];
	int fd_ag_infos = 0;
	__u64 *ag_sizes = malloc(MAX_AG_CNT * sizeof(__u64));
	FILE* fp_ag = NULL;
	time_t cur_time;									// used to get the current timestamp
	struct tm* info;									// translate the cur_time to local time
	struct xfsAG_bpf* obj = NULL;								// bpf object
	if(program_configure(argc, argv, &fp_ag, &config, &partitions, &partition))
		goto cleanup;
	if(bpf_initialize_and_load(&obj, &fd_ag_infos, &config, ag_sizes, partition, &xfs_config))
		goto cleanup;
	printf("Tracing a device with XFS filesystem... Hit Ctrl-C to end.\n");
	/* main: poll */
	my_print(fp_ag, true, "ag_count:%d", xfs_config.ag_count);
	while (!exiting) {
		sleep(config.interval);
		time(&cur_time);
		info = localtime(&cur_time);
		strftime(time_buffer, 80, "%Y-%m-%d %H:%M:%S", info);

		if(config.times <= 0)
			break;
		print_ag_infos(fd_ag_infos, fp_ag, time_buffer, &xfs_config);
		config.times--;
		if(config.times <= 0)
			break;
	}
cleanup:
	if(obj)
		xfsAG_bpf__destroy(obj);
	if(partitions)
		partitions__free(partitions);
	if(fp_ag)
		fclose(fp_ag);
	if(fd_ag_infos)
		close(fd_ag_infos);
	return 0;
}
