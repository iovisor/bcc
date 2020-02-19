# Demonstrations of filtering by cgroups

Some tools have an option to filter by cgroup by referencing a pinned BPF hash
map managed externally.

Examples of commands:

```
# ./opensnoop --cgroupmap /sys/fs/bpf/test01
# ./execsnoop --cgroupmap /sys/fs/bpf/test01
# ./tcpconnect --cgroupmap /sys/fs/bpf/test01
# ./tcpaccept --cgroupmap /sys/fs/bpf/test01
# ./tcptracer --cgroupmap /sys/fs/bpf/test01
```

The commands above will only display results from processes that belong to one
of the cgroups whose id, returned by `bpf_get_current_cgroup_id()`, is in the
pinned BPF hash map.

The BPF hash map can be created by:

```
# bpftool map create /sys/fs/bpf/test01 type hash key 8 value 8 entries 128 \
        name cgroupset flags 0
```

To get a shell in a new cgroup, you can use:

```
# systemd-run --pty --unit test bash
```

The shell will be running in the cgroup
`/sys/fs/cgroup/unified/system.slice/test.service`.

The cgroup id can be discovered using the `name_to_handle_at()` system call. In
the examples/cgroupid, you will find an example of program to get the cgroup
id.

```
# cd examples/cgroupid
# make
# ./cgroupid hex /sys/fs/cgroup/unified/system.slice/test.service
```

or, using Docker:

```
# cd examples/cgroupid
# docker build -t cgroupid .
# docker run --rm --privileged -v /sys/fs/cgroup:/sys/fs/cgroup \
	cgroupid cgroupid hex /sys/fs/cgroup/unified/system.slice/test.service
```

This prints the cgroup id as a hexadecimal string in the host endianness such
as `77 16 00 00 01 00 00 00`.

```
# FILE=/sys/fs/bpf/test01
# CGROUPID_HEX="77 16 00 00 01 00 00 00"
# bpftool map update pinned $FILE key hex $CGROUPID_HEX value hex 00 00 00 00 00 00 00 00 any
```

Now that the shell started by systemd-run has its cgroup id in the BPF hash
map, bcc tools will display results from this shell. Cgroups can be added and
removed from the BPF hash map without restarting the bcc tool.

This feature is useful for integrating bcc tools in external projects.
