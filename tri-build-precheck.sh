
# Step 1. Check necessary kernel config options

KERNEL_CONFIG_FILE=/boot/config-$(uname -r)

# https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_NET_CLS_BPF=m   # [optional, for tc filters]
# CONFIG_NET_ACT_BPF=m   # [optional, for tc actions]
# CONFIG_BPF_JIT=y
# CONFIG_HAVE_EBPF_JIT=y # [for Linux kernel versions 4.7 and later]
# CONFIG_BPF_EVENTS=y    # [optional, for kprobes]
# CONFIG_IKHEADERS=y     # Need kernel headers through /sys/kernel/kheaders.tar.xz
#
# CONFIG_NET_SCH_SFQ=m
# CONFIG_NET_ACT_POLICE=m
# CONFIG_NET_ACT_GACT=m
# CONFIG_DUMMY=m
# CONFIG_VXLAN=m

# TODO: check all the necessary ones
for c in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_NET_CLS_BPF CONFIG_NET_ACT_BPF; do
    grep "$c=" $KERNEL_CONFIG_FILE
done

# Step 2. Check or install build toolchain
# https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source

# For Ubuntu 22.04
sudo apt update -y # a necessay step otherwise you may get errors like "libllvm14-dev not found"
sudo apt install -y bison build-essential cmake flex git libedit-dev \
    libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-distutils
