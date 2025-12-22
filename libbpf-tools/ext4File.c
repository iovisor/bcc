// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//  Copyright (c) 2025 Samsung Electronics Co., Ltd.
#include <argp.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <bpf/bpf.h>
#include "ext4File.skel.h"
#include "trace_helpers.h"
#include "ext4File.h"

#define BG_LIST_NUM 57232

struct config {
	char* dir;
	char* dev;
	time_t interval;
	int times;
}config = {
	.interval = 100000000,
	.times = 100000000,
};

static volatile bool exiting;

void print_usage(FILE* fp, int argc, char** argv) {
    fprintf(fp,
        "Show ext4 files information.\n"
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
        "  %s -d /mnt/ext4              # Trace the device mounted on '/mnt/ext4'\n"
        "  %s -d /mnt/ext4 1 10         # Print 10 reports at 1 second intervals\n",
        argv[0], argv[0], argv[0]);
}

int parse_opt(int argc, char** argv) {
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
            config.dir = optarg;
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
        config.interval = atoi(argv[optind++]);
        if (optind < argc) {
            config.times = atoi(argv[optind++]);
        }
    }

    return 0;
}

__u64 get_system_boot_time() {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) {
        perror("Failed to open /proc/stat");
        return -1;
    }
    char line[256];
    __u64 boot_time = -1;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "btime", 5) == 0) {
            sscanf(line + 6, "%lld", &boot_time);
            break;
        }
    }
    fclose(fp);
    return boot_time;
}

void sig_handler(int sig) {
	exiting = true;
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

void get_device_name_from_path(const char* mount_dev, char* device_name) {
    int len = strlen(mount_dev);
    int pos;
    for (pos = len - 1; pos >= 0; pos--) {
        if (mount_dev[pos] == '/') break;
    }
    pos = pos >= 0 ? pos + 1 : 0;
    memcpy(device_name, mount_dev + pos, len - pos);
}

void ext4_info_get(struct ext4_config* ext4_config) {
    int fd_ext4_dev;

    fd_ext4_dev = open(config.dev, O_RDONLY);
    if (fd_ext4_dev < 0) {
        fprintf(stderr, "failed to open %s\n", config.dev);
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

void print_file_infos(int fdT, int fd_bg, char* time_buffer, FILE* fp_output) {
    int err;
    char time_zero[] = "---- -- -- --:--:--";
    struct file_info_key lookup_key = {}, next_key;
    struct file_info_val fiv;
    struct file_bg_key fbgk = {};
    int read_cnt, write_cnt;
    fprintf(fp_output, "%s\n", time_buffer);
    fprintf(fp_output, "%-10s %-20s %-10s %15s %10s %10s"
        " %10s %10s %10s %20s %20s %20s %20s %20s\n",
        "inode", "file_name", "pa_inode", "size", "hint", 
        "write", "read", "update", "access",
        "create_time", "access_time", "modify_time", "delete_time", "bg_id");
    while (!bpf_map_get_next_key(fdT, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fdT, &next_key, &fiv);
        if (err < 0) {
            fprintf(stderr, 
                "failed to lookup err: %u\n", err);
            return;
        }
        char ts[TS_TYPE_CNT][20];
        struct tm* time_info;
        for (int i = 0; i < TS_TYPE_CNT; i++) {
            if (fiv.fv_ts[i] == 0) {
                memcpy(ts[i], time_zero, sizeof(ts[i]));
            }
            else {
                time_t time_val = (time_t)fiv.fv_ts[i];
                time_info = localtime(&time_val);
                strftime(ts[i], 20, "%Y-%m-%d %H:%M:%S", time_info);
            }
        }
        write_cnt = fiv.fv_rw_cnt[RW_TYPE_DIRECT_WRITE] +
            fiv.fv_rw_cnt[RW_TYPE_BUFFER_WRITE];
        read_cnt = fiv.fv_rw_cnt[RW_TYPE_DIRECT_READ] +
            fiv.fv_rw_cnt[RW_TYPE_BUFFER_READ];
        fprintf(fp_output, "%-10u %-20s %-10u %15lld %10d ",
            next_key.fk_ino, next_key.fk_name, next_key.fk_pa_ino,
            fiv.fv_size, fiv.fv_hint);
        fprintf(fp_output, "%10d %10d %10d %10d",
            write_cnt, read_cnt, fiv.fv_update_cnt, fiv.fv_access_cnt);
        fprintf(fp_output, "%20s %20s %20s %20s",
            ts[TS_TYPE_CREATE], ts[TS_TYPE_ACCESS],
            ts[TS_TYPE_MODIFY], ts[TS_TYPE_DELETE]);
        fbgk.bgk_fik = next_key;
        fprintf(fp_output, "      [");
        int flag1 = 0;
        __u64 bg_bit;
        for (int k = 0; k < 1024; k++) {
            fbgk.bgk_index = k;
            err = bpf_map_lookup_elem(fd_bg, &fbgk, &bg_bit);
            if (err < 0) {
                continue;
            }

            while(bg_bit) {
                __u64 last_index = bg_bit;
                bg_bit = (bg_bit - 1) & bg_bit;
                int res = log2((last_index - bg_bit));
                int bg_id = fbgk.bgk_index * 64 + res;
                if (flag1 == 0) {
                    fprintf(fp_output, "%d", bg_id);
                    flag1++;
                } else {
                    fprintf(fp_output, ",%d", bg_id);
                }

            }
        }
        fprintf(fp_output, "]\n");
        lookup_key = next_key;
    }
}

int program_configure(int argc, char** argv, FILE** fp_output,
    struct partitions** partitions, const struct partition** partition) {
    const char* fs_type = "ext4";
    const char* log_path = "files_info.txt";
    char device_name[20];
    char mount_type[50];
    config.dev = malloc(256);
    memset(config.dev, 0, 256);

    if (parse_opt(argc, argv)) {
        fprintf(stderr, "error: parse_opt failed!\n");
        return -1;
    }
    if (!config.dir) {
        fprintf(stderr, "error: the FS mouned dir is needed\n");
        return -1;
    }

    //if the dev is mounted or made by ext4
    if (get_mounts_dev_by_dir(config.dev, config.dir, mount_type)) {
        fprintf(stderr, "error: failed to find %s\n", config.dir);
        return -1;
    }
    if (strcmp(fs_type, mount_type)) {
        fprintf(stderr, "error: the fs is not ext4\n");
        return -1;
    }

    // get the device_name(eg. get 'nvme0n1' from '/dev/nvme0n1')
    get_device_name_from_path(config.dev, device_name);
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
    *fp_output = fopen(log_path, "w");
    if (!*fp_output) {
        fprintf(stderr, "error: failed to open %s\n", log_path);
        return -1;
    }

    /* INT EVENT */
    signal(SIGINT, sig_handler);
    return 0;
}

int bpf_initialize_and_load(struct ext4File_bpf** objp, const struct partition* partition, struct ext4_config* ext4_config) {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    *objp = ext4File_bpf__open_opts(&open_opts);
    if (!*objp) {
        fprintf(stderr, "failed to open BPF object\n");
        return -1;
    }

    if (ext4File_bpf__load(*objp)) {
        fprintf(stderr, "failed to load BPF object\n");
        return -1;
    }

    ext4_info_get(ext4_config);
    (*objp)->bss->system_up = get_system_boot_time();
    (*objp)->bss->blocks_per_group = ext4_config->blocks_per_group;
    (*objp)->bss->device_num = partition->dev;

    if (ext4File_bpf__attach(*objp)) {
        fprintf(stderr, "failed to attach BPF programs\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    FILE* fp_output = NULL;
    char time_buffer[20];
    struct ext4_config ext4_config = {};
    struct partitions* partitions = NULL;
    const struct partition* partition = NULL;
    struct ext4File_bpf* obj = NULL;
    time_t cur_time;
    struct tm* info;
    if (program_configure(argc, argv, &fp_output, &partitions, &partition))
        goto cleanup;
    if (bpf_initialize_and_load(&obj, partition, &ext4_config))
        goto cleanup; 
    
    int fdT = bpf_map__fd(obj->maps.file_info_map);
	int fd_bg = bpf_map__fd(obj->maps.file_bg_map);

    printf("blocks_count:%d blocks_per_group:%d bg_cnt:%d\n", ext4_config.blocks_count, ext4_config.blocks_per_group, ext4_config.bg_cnt);
    printf("Tracing Ext4 read/write... Hit Ctrl-C to end.\n");
	while (!exiting) {
        sleep(config.interval);
        time(&cur_time);
        info = localtime(&cur_time);
        strftime(time_buffer, 80, "%Y-%m-%d %H:%M:%S", info);

        print_file_infos(fdT, fd_bg, time_buffer, fp_output);
        config.times--;
        if (config.times <= 0)
            break;
    }
    close(fd_bg);
    close(fdT);
cleanup:
    if(obj)
        ext4File_bpf__destroy(obj);
    if(partitions)
        partitions__free(partitions);
    if(fp_output)
        fclose(fp_output);
    return 0;
}
