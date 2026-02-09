// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2026 Samsung Electronics Co., Ltd.
#include <argp.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <bpf/bpf.h>
#include "ext4file.skel.h"
#include "trace_helpers.h"
#include "ext4file.h"

#define BG_LIST_NUM 57232

struct config {
	char *dir;
    char *output_file;
	char *dev;
	time_t interval;
	int times;
}config = {
	.interval = 100000000,
	.times = 100000000,
};

static volatile bool exiting;

void print_usage(FILE *fp, int argc, char **argv) {
    fprintf(fp,
        "Show I/O pattern for every file in ext4 filesystem\n"
        "\n"
        "Usage: %s [-h] [-d DIR] [-o FILE] [interval] [count]\n"
        "\n"
        "Options:\n"
        "  -h, --help                   Print this help message\n"
        "  -d DIR, --dir=DIR            Trace the ext4 filesystem mounted on the specified directory\n"
        "  -o FILE, --output=FILE       Write output to a file (optional; default: stdout)\n"
        "  interval                     Time interval (in seconds) between reports (default: unlimited)\n"
        "  count                        Number of reports to generate (default: unlimited)\n"
        "\n"
        "Examples:\n"
        "  %s -d /mnt/ext4                      # Trace I/O patterns of files on the ext4 filesystem mounted at /mnt/ext4\n"
        "  %s -d /mnt/ext4 1 10                 # Generate 10 reports, one per second\n"
        "  %s -d /mnt/ext4 -o output 1 10       # Generate 10 reports at 1-second intervals, saving output to ./output\n",
        argv[0], argv[0], argv[0], argv[0]);
}

int parse_opt(int argc, char **argv) {
    int c;
    int option_index = 0;
    static struct option long_options[] = {
        {"dir", required_argument, 0, 'd'},
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "d:o:h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'd':
            config.dir = optarg;
            break;
        case 'h':
            print_usage(stdout, argc, argv);
            exit(0);
        case 'o':
            if (optarg)
                config.output_file = optarg;
            else
                config.output_file = NULL;
            break;
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
        config.interval = atoi(argv[optind++]);
        if (optind < argc) {
            config.times = atoi(argv[optind++]);
        }
    }

    return 0;
}

void targeted_printf(int fd_output, const char *format, ...){
    va_list args;
    va_start(args, format);

    char buf[1024];
    int len;
    len = vsnprintf(buf, sizeof(buf), format, args);

    va_end(args);
    if (fd_output >= 0)
        write(fd_output, buf, len);
    else if (fd_output == FD_STDOUT)
        fwrite(buf, 1, len, stdout);
    else if (fd_output == FD_STDERR)
        fwrite(buf, 1, len, stderr);
}

void sig_handler(int sig) {
	exiting = true;
}

int get_mounts_dev_by_dir(const char *dev, char *dir, char *type) {
    FILE *f = NULL;
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

void get_device_name_from_path(const char *mount_dev, char *device_name) {
    int len = strlen(mount_dev);
    int pos;
    for (pos = len - 1; pos >= 0; pos--) {
        if (mount_dev[pos] == '/') break;
    }
    pos = pos >= 0 ? pos + 1 : 0;
    memcpy(device_name, mount_dev + pos, len - pos);
}

void ext4_info_get(struct ext4_config *ext4_config) {
    int fd_ext4_dev;

    fd_ext4_dev = open(config.dev, O_RDONLY);
    if (fd_ext4_dev < 0) {
        targeted_printf(FD_STDERR, "failed to open %s\n", config.dev);
        goto cleanup;
    }
    pread(fd_ext4_dev, &ext4_config->blocks_per_group, 4, 1056);
    pread(fd_ext4_dev, &ext4_config->blocks_count, 4, 1028);
    ext4_config->bg_cnt = 
        ext4_config->blocks_count / ext4_config->blocks_per_group;

cleanup:
    if (fd_ext4_dev > 0)
        close(fd_ext4_dev);
}

void print_file_infos(int fdT, char *time_buffer, int fd_output) {
    int err;
    struct file_info_key lookup_key = {}, next_key;
    struct file_info_val fiv;
    targeted_printf(fd_output, "%s\n", time_buffer);
    targeted_printf(fd_output, "%-10s %-20s %-10s %-6s "
        "%-15s %-15s %-15s %-15s %-8s\n",
        "file_name", "inode", "pa_inode", "hint", 
        "buffer_read", "direct_read", "buffer_write", "direct_write", "delete");
    while (!bpf_map_get_next_key(fdT, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fdT, &next_key, &fiv);
        if (err < 0) {
            targeted_printf(FD_STDERR, 
                "failed to lookup err: %u\n", err);
            return;
        }
        targeted_printf(fd_output, "%-10u %-20s %-10u %-6u ",
            next_key.fk_name, next_key.fk_ino, next_key.fk_pa_ino, fiv.fv_hint);
        targeted_printf(fd_output, "%-15d %-15d %-15d %-15d ",
            fiv.fv_rw_cnt[RW_TYPE_BUFFER_READ], fiv.fv_rw_cnt[RW_TYPE_DIRECT_READ], 
            fiv.fv_rw_cnt[RW_TYPE_BUFFER_WRITE], fiv.fv_rw_cnt[RW_TYPE_DIRECT_WRITE]);
        targeted_printf(fd_output, "%-8s\n",
            fiv.fv_delete ? "True": "False");
        lookup_key = next_key;
    }
}

int program_configure(int argc, char **argv, int *fd_output,
    struct partitions **partitions, const struct partition **partition) {
    const char *fs_type = "ext4";
    char device_name[20];
    char mount_type[10];
    config.dev = malloc(256);
    memset(config.dev, 0, 256);

    if (parse_opt(argc, argv)) {
        targeted_printf(FD_STDERR, "error: parse_opt failed!\n");
        return -1;
    }
    if (!config.dir) {
        targeted_printf(FD_STDERR, "error: the FS mounted dir is needed\n");
        return -1;
    }

    //if the dev is mounted or made by ext4
    if (get_mounts_dev_by_dir(config.dev, config.dir, mount_type)) {
        targeted_printf(FD_STDERR, 
            "error: failed to find %s, you can refer to \"df -h\"\n", config.dir);
        return -1;
    }
    if (strcmp(fs_type, mount_type)) {
        targeted_printf(FD_STDERR, "error: the fs is not ext4\n");
        return -1;
    }

    // get the device_name(eg. get 'nvme0n1' from '/dev/nvme0n1')
    get_device_name_from_path(config.dev, device_name);

    *partitions = partitions__load();
    if (!*partitions) {
        targeted_printf(FD_STDERR, "error: failed to load partitions\n");
        return -1;
    }
    *partition = partitions__get_by_name(*partitions, device_name);
    if (!*partition) {
        targeted_printf(FD_STDERR, "error: failed to find the %s in partitions\n", device_name);
        return -1;
    }
    if (config.output_file) {
        *fd_output = open(config.output_file, O_WRONLY | O_CREAT);
        if (*fd_output == -1) {
            targeted_printf(FD_STDERR, "error: failed to open %s\n", config.output_file);
            return -1;
        }
    }
    /* INT EVENT */
    signal(SIGINT, sig_handler);
    return 0;
}

int bpf_initialize_and_load(struct ext4file_bpf **objp, const struct partition *partition, struct ext4_config *ext4_config) {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    *objp = ext4file_bpf__open_opts(&open_opts);
    if (!*objp) {
        targeted_printf(FD_STDERR, "failed to open BPF object\n");
        return -1;
    }

    if (ext4file_bpf__load(*objp)) {
        targeted_printf(FD_STDERR, "failed to load BPF object\n");
        return -1;
    }

    ext4_info_get(ext4_config);
    (*objp)->bss->blocks_per_group = ext4_config->blocks_per_group;
    (*objp)->bss->dev_target = partition->dev;

    if (ext4file_bpf__attach(*objp)) {
        targeted_printf(FD_STDERR, "failed to attach BPF programs\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    int fd_output = FD_STDOUT;
    char time_buffer[20];
    struct ext4_config ext4_config = {};
    struct partitions *partitions = NULL;
    const struct partition *partition = NULL;
    struct ext4file_bpf *obj = NULL;
    time_t cur_time;
    struct tm *info;
    if (program_configure(argc, argv, &fd_output, &partitions, &partition))
        goto cleanup;
    if (bpf_initialize_and_load(&obj, partition, &ext4_config))
        goto cleanup; 
    
    int fd_map_ffm = bpf_map__fd(obj->maps.file_info_map);

    targeted_printf(FD_STDOUT, "interval: %u\n", config.interval);
    targeted_printf(FD_STDOUT, "EXT4 FS Info: blocks_count=%u blocks_per_group=%u bg_cnt=%u\n", ext4_config.blocks_count, ext4_config.blocks_per_group, ext4_config.bg_cnt);
    targeted_printf(FD_STDOUT, "Tracing Ext4 read/write... Hit Ctrl-C to end.\n");
    
	while (!exiting) {
        sleep(config.interval);
        time(&cur_time);
        info = localtime(&cur_time);
        strftime(time_buffer, 80, "%Y-%m-%d %H:%M:%S", info);

        print_file_infos(fd_map_ffm, time_buffer, fd_output);
        config.times--;
        if (config.times <= 0)
            break;
    }
    close(fd_map_ffm);
cleanup:
    if(obj)
        ext4file_bpf__destroy(obj);
    if(partitions)
        partitions__free(partitions);
    if(fd_output > -1)
        close(fd_output);
    return 0;
}
