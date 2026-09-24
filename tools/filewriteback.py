#! /usr/bin/python3
from time import sleep, strftime
import argparse
import os
import subprocess
import json
from requests.exceptions import RequestException
from bcc import BPF

OUTPUT_FILES = [
        "IOflame.write.iops",
        "IOflame.write.bandwidth",
        "IOflame.write.times"
]
OUTPUT_DIR = "IOflamefiles"
REQ_OP_BITS = 8
REQ_OP_MASK = ((1 << REQ_OP_BITS) - 1)

examples = """examples:
    ./filewriteback.py         # get write IOPs/bandwidth/times and store in
                               # IOflamefiles directory
    ./filewriteback.py 10      # 10 sec's duration
"""
parser = argparse.ArgumentParser(
    description="""Summarize write IOPs/bandwidth/times in folded stack format.
    The info will be stored in three files which are IOflame.write.iops,
    IOflame.write.bandwidth, IOflame.write.times in the directory IOflamefiles.
    """,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("duration", nargs="?", default=60, type=int,
    help="data collection duration, in seconds")
args = parser.parse_args()

bpf_text = """
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/types.h>
#include <linux/blk-mq.h>

#ifndef containerof
#define containerof(ptr, type, member) ({          \
            const typeof(((type *)0)->member)*__mptr = (ptr);    \
                (type *)((char *)__mptr - offsetof(type, member)); })
#endif

#define FILE_NUM 40960
#define REQUEST_NUM 40960
#define PATH_NUM 102400
#define MAX_DENTRY 18

typedef struct file_key {
    dev_t dev;
    unsigned long i_ino;
    signed long tv_sec;
    long tv_nsec;
} file_key_t;

typedef struct file_req_key {
    file_key_t req_key;
    unsigned long cmd_flags;
} file_req_key_t;

typedef struct file_path_key {
    file_key_t path_key;
    unsigned long depth;
} file_path_key_t;

//If each path_part contains only one dentry, the file_full_path may be full
//quickly. We use three dentries in one path_part.
typedef struct path_part {
    char path_name0[DNAME_INLINE_LEN];
    char path_name1[DNAME_INLINE_LEN];
    char path_name2[DNAME_INLINE_LEN];
} path_part_t;

BPF_HASH(file_exist, struct file_key, bool, FILE_NUM);
BPF_HASH(file_req, struct file_req_key, unsigned int, REQUEST_NUM);
BPF_HASH(file_full_path, struct file_path_key, struct path_part, PATH_NUM);
BPF_HASH(file_bandwidth, struct file_req_key, unsigned int, REQUEST_NUM);

int trace_path(struct pt_regs *ctx, struct request *req)
{
    struct inode *inode_addr = req->bio->bi_io_vec->bv_page->mapping->host;
    struct hlist_head identry;
    bpf_probe_read_kernel(&identry, sizeof(identry), &inode_addr->i_dentry);
    struct dentry *dentry_addr = containerof(identry.first,
                                 struct dentry,
                                 d_u.d_alias);

    //From the struct of ext4_inode_info, we find that btime address equals
    //inode address plus sizes of struct inode, struct jbd2_inode *, spinlock_t
    struct timespec64 *btime = (struct timespec64 *)((char *)inode_addr +
                                sizeof(struct inode) + 0x10);
    unsigned long tv_sec = btime->tv_sec;
    long tv_nsec = btime->tv_nsec;
    struct file_key key = {
        .dev = __DEV__,
        .i_ino = inode_addr->i_ino,
        .tv_sec = (inode_addr->i_ino > 0) ? tv_sec : 0,
        .tv_nsec = (inode_addr->i_ino > 0) ? tv_nsec : 0
    };

    struct file_req_key req_ins = {
        .req_key = key,
        .cmd_flags = req->cmd_flags
    };

    file_req.atomic_increment(req_ins);
    file_bandwidth.atomic_increment(req_ins, req->__data_len/1024);

    if (!file_exist.lookup(&key))
    {
        bool exist = true;

        file_exist.update(&key, &exist);
        int loop = 0;
        struct path_part path_ins;
        struct qstr d_name;
        struct dentry *de0;
        struct dentry *de1;
        struct dentry *de2;
        __builtin_memset(&path_ins, 0, sizeof(path_ins));
        __builtin_memset(&d_name, 0, sizeof(d_name));

        bpf_probe_read_kernel(&de0, sizeof(de0), &dentry_addr);

        #pragma clang loop unroll(full)
        while (loop < MAX_DENTRY / 3)
        {
            bpf_probe_read_kernel(&d_name, sizeof(d_name), &de0->d_name);
            bpf_probe_read_kernel(&path_ins.path_name0,
                                  sizeof(path_ins.path_name0),
                                  d_name.name);

            bpf_probe_read_kernel(&de1, sizeof(de1), &de0->d_parent);
            bpf_probe_read_kernel(&d_name, sizeof(d_name), &de1->d_name);
            bpf_probe_read_kernel(&path_ins.path_name1,
                                  sizeof(path_ins.path_name1),
                                  d_name.name);

            bpf_probe_read_kernel(&de2, sizeof(de2), &de1->d_parent);
            bpf_probe_read_kernel(&d_name, sizeof(d_name), &de2->d_name);
            bpf_probe_read_kernel(&path_ins.path_name2,
                                  sizeof(path_ins.path_name2),
                                  d_name.name);
            struct file_path_key path_key_ins = {
                .path_key = key,
                .depth = loop
            };
            file_full_path.update(&path_key_ins, &path_ins);
            bpf_probe_read_kernel(&de0, sizeof(de0), &de2->d_parent);
            if (de0 == de2)
            {
                break;
            }
            loop++;
        }
    }
    return 0;
}

"""

def run_cmd(cmd):
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False
        )
        if res.returncode == 0:
            return True, res.stdout
        else:
            print("error:", res.stderr)
            exit()
    except subprocess.CalledProcessError as e:
        print("command failed: {}".format(e))
        exit()

def get_mount_info():
    lsblk = ["lsblk", "-o", "NAME,MAJ:MIN,MOUNTPOINT", "-J"]
    success, mount = run_cmd(lsblk)
    if success is True:
        print("get mount info success")
        return json.loads(mount)['blockdevices']


mount_info = get_mount_info()

if BPF.kernel_struct_has_field(b'block_device', b'bd_part') == 0:
    bpf_text = bpf_text.replace('__DEV__', 'req->part->bd_dev')
else:
    bpf_text = bpf_text.replace('__DEV__', 'req->part->__dev.devt')

b = BPF(text=bpf_text)
if BPF.get_kprobe_functions(b'blk_mq_start_request'):
    b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_path")

partition = {}
def get_mount_entry(entry):
    major, minor = entry['maj:min'].split(':')
    dev = (int(major) << 20 | int(minor))
    if entry['mountpoint'] is not None:
        partition[dev] = entry['name'], entry['mountpoint']


for entry in mount_info:
    get_mount_entry(entry)
    if 'children' in entry:
        for child_entry in entry['children']:
            get_mount_entry(child_entry)

# The full_path contains path components, we merge the components of the same
# inode into one flattened full path
def merge_path(full_path):
    for key in full_path:
        path = full_path[key]
        tmpfp = list()
        # To ensure the path in the right order, need to sort by the path depth
        for i in sorted(path):
            tmpfp = tmpfp + list(path[i])
        fp_flattened = list()
        for i in range(len(tmpfp)):
            if i == len(tmpfp) - 1:
                fp_flattened.append(tmpfp[i])
                break
            if (tmpfp[i] == "/") and (tmpfp[i + 1] == "/"):
                fp_flattened.append(tmpfp[i])
                break
            fp_flattened.append(tmpfp[i])
        full_path[key] = fp_flattened

    full_path_merge = {}
    for key in full_path:
        path = full_path[key]
        s = ""
        for i in range(len(path)):
            if i == len(path) - 1:
                if key[0] in partition:
                    s = partition[key[0]][1] + s
                break
            s = ";" + path[i] + s
        full_path_merge[key] = s
    return full_path_merge

def main():
    print("Tracing file writeback... Hit Ctrl-C to end")
    try:
        sleep(int(args.duration))
    except KeyboardInterrupt:
        print('\nkeyboardInterrupt')
    b.detach_kprobe(event="blk_mq_start_request", fn_name="trace_path")

    b['file_exist'].clear()

    full_path = {}
    for k, v in b.get_table("file_full_path").items():
        key = k.path_key.dev, k.path_key.i_ino,\
                k.path_key.tv_sec, k.path_key.tv_nsec
        value = {}
        if key in full_path:
            value = full_path[key]
        value[k.depth] = v.path_name0.decode('utf-8'),\
                            v.path_name1.decode('utf-8'),\
                            v.path_name2.decode('utf-8')
        full_path[key] = value
    full_path_merge = merge_path(full_path)

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    os.chdir(OUTPUT_DIR)

    path_write = {}
    f = open(OUTPUT_FILES[0], 'w')
    for k, v in b.get_table("file_req").items():
        key = k.req_key.dev, k.req_key.i_ino,\
                k.req_key.tv_sec, k.req_key.tv_nsec
        if (k.cmd_flags & REQ_OP_MASK) == 1 and key in full_path_merge:
            line = full_path_merge[key] + " " + str(v.value)
            path_write[key] = full_path_merge[key]
            f.write(line + "\n")
    f.close()

    f = open(OUTPUT_FILES[1], 'w')
    for k, v in b.get_table('file_bandwidth').items():
        key = k.req_key.dev, k.req_key.i_ino,\
                k.req_key.tv_sec, k.req_key.tv_nsec
        if (k.cmd_flags & REQ_OP_MASK) == 1 and key in full_path_merge:
            line = full_path_merge[key] + " " + str(v.value)
            f.write(line + "\n")
    f.close()

    path_write_times = {}
    for k, v in path_write.items():
        if k[1] <= 0:
            continue
        if v in path_write_times:
            path_write_times[v] += 1
        else:
            path_write_times[v] = 1

    f = open(OUTPUT_FILES[2], 'w')
    for k, v in path_write_times.items():
        line = k + " " + str(v)
        f.write(line + "\n")
    f.close()

    b['file_full_path'].clear()
    b['file_req'].clear()
    b['file_bandwidth'].clear()

    print("Trace ends, please analyze with the files stored in IOflamefiles.")

    exit()


if __name__ == '__main__':
    main()
