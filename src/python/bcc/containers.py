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
        atomic_t count;
        struct ns_common ns;
    };

    BPF_TABLE_PINNED("hash", u64, u32, mount_ns_set, 1024, "MOUNT_NS_PATH");

    static inline int _mntns_filter() {
        struct task_struct *current_task;
        current_task = (struct task_struct *)bpf_get_current_task();
        u64 ns_id = current_task->nsproxy->mnt_ns->ns.inum;
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
