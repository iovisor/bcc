
## Fedora Demo VM

Before running the script, ensure that virt-install is available on the system.

`./build_bpf_demo.sh -n bpf-demo -k bpf_demo.ks.erb`

After setting up the initial VM, log in (the default password is 'iovisor')
and determine the DHCP IP. SSH to this IP as root.

To set up a kernel with the right options, run `bpf-kernel-setup`.

```
[root@bpf-demo ~]# bpf-kernel-setup
Cloning into 'net-next'...
```
After pulling the net-next branch, the kernel config menu should pop up. Ensure
that the below settings are proper.
```
General setup --->
  [*] Enable bpf() system call
Networking support --->
  Networking options --->
    QoS and/or fair queueing --->
      <M> BPF-based classifier
      <M> BPF based action
    [*] enable BPF Just In Time compiler
```
Once the .config is saved, the build will proceed and install the resulting
kernel. This kernel has updated userspace headers (e.g. the bpf() syscall) which
install into /usr/local/include...proper packaging for this will be
distro-dependent.

Next, run `bpf-llvm-setup` to pull and compile LLVM with BPF support enabled.
```
[root@bpf-demo ~]# bpf-llvm-setup
Cloning into 'llvm'...
```
The resulting libraries will be installed into /opt/local/llvm.

Next, reboot into the new kernel, either manually or by using the kexec helper.
```
[root@bpf-demo ~]# kexec-4.1.0-rc1+
Connection to 192.168.122.247 closed by remote host.
Connection to 192.168.122.247 closed.
```

Reconnect and run the final step, building and testing bcc.
```
[root@bpf-demo ~]# bcc-setup
Cloning into 'bcc'...
...
Linking CXX shared library libcc.so
[100%] Built target bcc
...
Running tests...
Test project /root/bcc/build
    Start 1: py_test1
1/4 Test #1: py_test1 .........................   Passed    0.24 sec
    Start 2: py_test2
2/4 Test #2: py_test2 .........................   Passed    0.53 sec
    Start 3: py_trace1
3/4 Test #3: py_trace1 ........................   Passed    0.09 sec
    Start 4: py_trace2
4/4 Test #4: py_trace2 ........................   Passed    1.06 sec

100% tests passed, 0 tests failed out of 4
```
