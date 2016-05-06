# Installing BCC

* [Kernel Configuration](#kernel-configuration)
* [Packages](#packages)
  - [Ubuntu](#ubuntu---binary)
  - [Fedora](#fedora---binary)
  - [Arch](#arch---aur)
* [Source](#source)
  - [Ubuntu](#ubuntu---source)
  - [Fedora](#fedora---source)
* [Older Instructions](#older-instructions)

## Kernel Configuration

In general, to use these features, a Linux kernel version 4.1 or newer is
required. In addition, the kernel should have been compiled with the following
flags set:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
# [optional, for tc filters]
CONFIG_NET_CLS_BPF=m
# [optional, for tc actions]
CONFIG_NET_ACT_BPF=m
CONFIG_BPF_JIT=y
CONFIG_HAVE_BPF_JIT=y
# [optional, for kprobes]
CONFIG_BPF_EVENTS=y
```

Kernel compile flags can usually be checked by looking at `/proc/config.gz` or
`/boot/config-<kernel-version>`.

# Packages

## Ubuntu Xenial - Binary

Only the nightly packages are built for Ubuntu 16.04, but the steps are very straightforward. No need to upgrade the kernel or compile from source!

```bash
echo "deb [trusted=yes] http://52.8.15.63/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools
```

## Ubuntu Trusty - Binary

**Kernel**

Install a 4.3+ kernel from http://kernel.ubuntu.com/~kernel-ppa/mainline,
for example:

```bash
VER=4.5.1-040501
PREFIX=http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.5.1-wily/
REL=201604121331
wget ${PREFIX}/linux-headers-${VER}-generic_${VER}.${REL}_amd64.deb
wget ${PREFIX}/linux-headers-${VER}_${VER}.${REL}_all.deb
wget ${PREFIX}/linux-image-${VER}-generic_${VER}.${REL}_amd64.deb
sudo dpkg -i linux-*${VER}.${REL}*.deb
# reboot
```

Update PREFIX to the latest date, and you can browse the files in the PREFIX url to find the REL number.

**Signed Packages**

Tagged and signed bcc binary packages are built for Ubuntu Trusty (14.04) and
hosted at http://52.8.15.63/apt/.

To install:
```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
echo "deb http://52.8.15.63/apt trusty main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install binutils bcc bcc-tools libbcc-examples python-bcc
```

**Nightly Packages**

```bash
echo "deb [trusted=yes] http://52.8.15.63/apt/trusty trusty-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools
```

Test it:
```
sudo python /usr/share/bcc/examples/hello_world.py
sudo python /usr/share/bcc/examples/tracing/task_switch.py
```

(Optional) Install pyroute2 for additional networking features
```bash
git clone https://github.com/svinota/pyroute2
cd pyroute2; sudo make install
sudo python /usr/share/bcc/examples/simple_tc.py
```

## Fedora - Binary

Install a 4.2+ kernel from
http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug, for example:

```bash
sudo dnf config-manager --add-repo=http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug/fedora-rawhide-kernel-nodebug.repo
sudo dnf update
# reboot
```

Nightly bcc binary packages are built for Fedora 23 and 24, hosted at
`http://52.8.15.63/yum/nightly/f{23,24}`.

To install (change 'f23' to 'f24' for rawhide):
```bash
echo -e '[iovisor]\nbaseurl=http://52.8.15.63/yum/nightly/f23/$basearch\nenabled=1\ngpgcheck=0' | sudo tee /etc/yum.repos.d/iovisor.repo
sudo dnf install bcc-tools
```

## Arch - AUR

Upgrade the kernel to minimum 4.3.1-1 first; the ```CONFIG_BPF_SYSCALL=y``` configuration was not added until [this kernel release](https://bugs.archlinux.org/task/47008).

Install these packages using any AUR helper such as [pacaur](https://aur.archlinux.org/packages/pacaur), [yaourt](https://aur.archlinux.org/packages/yaourt), [cower](https://aur.archlinux.org/packages/cower), etc.:
```
bcc bcc-tools python-bcc python2-bcc
```
All build and install dependencies are listed [in the PKGBUILD](https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=bcc) and should install automatically.


# Source

## Ubuntu - Source

To build the toolchain from source, one needs:
* LLVM 3.7 or newer, compiled with BPF support (default=on)
* Clang 3.7, built from the same tree as LLVM
* cmake, gcc (>=4.7), flex, bison
* LuaJIT, if you want Lua support

### Install build dependencies
```
# Trusty and older
VER=trusty
echo "deb http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main
deb-src http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main" | \
  sudo tee /etc/apt/sources.list.d/llvm.list
wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update

# All versions
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev libelf-dev

# For Lua support
sudo apt-get -y install luajit luajit-5.1-dev
```

### Install and compile BCC
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

## Fedora - Source

### Install build dependencies

```
sudo dnf install -y bison cmake ethtool flex git iperf libstdc++-static \
  python-netaddr python-pip gcc gcc-c++ make zlib-devel
sudo dnf install -y luajit luajit-devel  # for Lua support
sudo dnf install -y \
  http://pkgs.repoforge.org/netperf/netperf-2.6.0-1.el6.rf.x86_64.rpm
sudo pip install pyroute2
```

### Install binary clang

```
wget http://llvm.org/releases/3.7.0/clang+llvm-3.7.0-x86_64-fedora22.tar.xz
sudo tar xf clang+llvm-3.7.0-x86_64-fedora22.tar.xz -C /usr/local --strip 1
```

### Install and compile BCC
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

# Older Instructions

## Build LLVM and Clang development libs

```
git clone http://llvm.org/git/llvm.git
cd llvm/tools; git clone http://llvm.org/git/clang.git
cd ..; mkdir -p build/install; cd build
cmake -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/install ..
make
make install
export PATH=$PWD/install/bin:$PATH
```
