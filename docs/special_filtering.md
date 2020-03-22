# Special Filtering

Some tools have special filtering capabitilies, the main use case is to trace
processes running in containers, but those mechanisms are generic and could
be used in other cases as well.

## Filtering by cgroups

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

## Filtering by mount by namespace

The BPF hash map can be created by:

```
# bpftool map create /sys/fs/bpf/mnt_ns_set type hash key 8 value 4 entries 128 \
        name mnt_ns_set flags 0
```

Execute the `execsnoop` tool filtering only the mount namespaces
in `/sys/fs/bpf/mnt_ns_set`:

```
# tools/execsnoop.py --mntnsmap /sys/fs/bpf/mnt_ns_set
```

Start a terminal in a new mount namespace:

```
# unshare -m bash
```

Update the hash map with the mount namespace ID of the terminal above:

```
FILE=/sys/fs/bpf/mnt_ns_set
if [ $(printf '\1' | od -dAn) -eq 1 ]; then
 HOST_ENDIAN_CMD=tac
else
  HOST_ENDIAN_CMD=cat
fi

NS_ID_HEX="$(printf '%016x' $(stat -Lc '%i' /proc/self/ns/mnt) | sed 's/.\{2\}/&\n/g' | $HOST_ENDIAN_CMD)"
bpftool map update pinned $FILE key hex $NS_ID_HEX value hex 00 00 00 00 any
```

Execute a command in this terminal:

```
# ping kinvolk.io
```

You'll see how on the `execsnoop` terminal you started above the call is logged:

```
# tools/execsnoop.py --mntnsmap /sys/fs/bpf/mnt_ns_set
[sudo] password for mvb:
PCOMM            PID    PPID   RET ARGS
ping             8096   7970     0 /bin/ping kinvolk.io
```
