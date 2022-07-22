# Copyright 2020 Kinvolk GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

def _cgroup_filter_func_writer(cgroupmap):
    if not cgroupmap:
        return """
        static inline int _cgroup_filter() {
            return 0;
        }
        """

    text = """
    BPF_TABLE_PINNED("hash", u64, u64, cgroupset, 1024, "CGROUP_PATH");

    static inline int _cgroup_filter() {
        u64 cgroupid = bpf_get_current_cgroup_id();
        return cgroupset.lookup(&cgroupid) == NULL;
    }
    """

    return text.replace('CGROUP_PATH', cgroupmap)

def _mntns_filter_func_writer(mntnsmap):
    if not mntnsmap:
        return """
        static inline int _mntns_filter() {
            return 0;
        }
        """
    text = """
    #include <linux/nsproxy.h>
    #include <linux/mount.h>
    #include <linux/ns_common.h>

    /* see mountsnoop.py:
    * XXX: struct mnt_namespace is defined in fs/mount.h, which is private
    * to the VFS and not installed in any kernel-devel packages. So, let's
    * duplicate the important part of the definition. There are actually
    * more members in the real struct, but we don't need them, and they're
    * more likely to change.
    */
    struct mnt_namespace {
    // This field was removed in https://github.com/torvalds/linux/commit/1a7b8969e664d6af328f00fe6eb7aabd61a71d13
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
        atomic_t count;
    #endif
        struct ns_common ns;
    };
    /*
     * To add mountsnoop support for --selector option, we need to call
     * filter_by_containers().
     * This function adds code which defines struct mnt_namespace.
     * The problem is that this struct is also defined in mountsnoop BPF code.
     * To avoid redefining it in mountnsoop code, we define
     * MNT_NAMESPACE_DEFINED here.
     * Then, in mountsnoop code, the struct mnt_namespace definition is guarded
     * by:
     * #ifndef MNT_NAMESPACE_DEFINED
     * // ...
     * #endif
     */
    #define MNT_NAMESPACE_DEFINED

    BPF_TABLE_PINNED("hash", u64, u32, mount_ns_set, 1024, "MOUNT_NS_PATH");

    static inline int _mntns_filter() {
        struct task_struct *current_task;
        struct nsproxy *nsproxy;
        struct mnt_namespace *mnt_ns;
        unsigned int inum;
        u64 ns_id;

        current_task = (struct task_struct *)bpf_get_current_task();

        if (bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &current_task->nsproxy))
            return 0;

        if (bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns))
            return 0;

        if (bpf_probe_read_kernel(&inum, sizeof(inum), &mnt_ns->ns.inum))
            return 0;

        ns_id =  (u64) inum;

        return mount_ns_set.lookup(&ns_id) == NULL;
    }
    """

    return text.replace('MOUNT_NS_PATH', mntnsmap)

def filter_by_containers(args):
    filter_by_containers_text = """
    static inline int container_should_be_filtered() {
        return _cgroup_filter() || _mntns_filter();
    }
    """

    cgroupmap_text = _cgroup_filter_func_writer(args.cgroupmap)
    mntnsmap_text = _mntns_filter_func_writer(args.mntnsmap)

    return cgroupmap_text + mntnsmap_text + filter_by_containers_text
