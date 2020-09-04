# Installing BCC

* [Kernel Configuration](#kernel-configuration)
* [Packages](#packages)
  - [Ubuntu](#ubuntu---binary)
  - [Fedora](#fedora---binary)
  - [Arch](#arch---aur)
  - [Gentoo](#gentoo---portage)
  - [openSUSE](#opensuse---binary)
  - [RHEL](#rhel---binary)
  - [Amazon Linux 1](#Amazon-Linux-1---Binary)
  - [Amazon Linux 2](#Amazon-Linux-2---Binary)
  - [Alpine](#alpine---binary)
* [Source](#source)
  - [Debian](#debian---source)
  - [Ubuntu](#ubuntu---source)
  - [Fedora](#fedora---source)
  - [openSUSE](#opensuse---source)
  - [Centos](#centos---source)
  - [Amazon Linux](#amazon-linux---source)
  - [Alpine](#alpine---source)
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
# [for Linux kernel versions 4.1 through 4.6]
CONFIG_HAVE_BPF_JIT=y
# [for Linux kernel versions 4.7 and later]
CONFIG_HAVE_EBPF_JIT=y
# [optional, for kprobes]
CONFIG_BPF_EVENTS=y
```

There are a few optional kernel flags needed for running bcc networking examples on vanilla kernel:

```
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_ACT_POLICE=m
CONFIG_NET_ACT_GACT=m
CONFIG_DUMMY=m
CONFIG_VXLAN=m
```

Kernel compile flags can usually be checked by looking at `/proc/config.gz` or
`/boot/config-<kernel-version>`.

# Packages

## Ubuntu - Binary

Versions of bcc are available in the standard Ubuntu
Universe repository, as well in iovisor's PPA. The Ubuntu packages have slightly different names: where iovisor
packages use `bcc` in the name (e.g. `bcc-tools`), Ubuntu packages use `bpfcc` (e.g.
`bpfcc-tools`).

Currently, BCC packages for both the Ubuntu Universe, and the iovisor builds are outdated. This is a known and tracked in:
- [Universe - Ubuntu Launchpad](https://bugs.launchpad.net/ubuntu/+source/bpfcc/+bug/1848137)
- [iovisor - BCC GitHub Issues](https://github.com/iovisor/bcc/issues/2678)
Currently, [building from source](#ubuntu---source) is currently the only way to get up to date packaged version of bcc.

**Ubuntu Packages**
Source packages and the binary packages produced from them can be
found at [packages.ubuntu.com](https://packages.ubuntu.com/search?suite=default&section=all&arch=any&keywords=bpfcc&searchon=sourcenames).

```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

The tools are installed in `/sbin` (`/usr/sbin` in Ubuntu 18.04) with a `-bpfcc` extension. Try running `sudo opensnoop-bpfcc`.

**_Note_**: the Ubuntu packages have different names but the package contents, in most cases, conflict
and as such _cannot_ be installed alongside upstream packages. Should one choose to use
Ubuntu's packages instead of the upstream iovisor packages (or vice-versa), the
conflicting packages will need to be removed.

The iovisor packages _do_ declare they provide the Ubuntu packages and as such may be
used to satisfy dependencies. For example, should one attempt to install package `foo`
which declares a dependency on `libbpfcc` while the upstream `libbcc` package is installed,
`foo` should install without trouble as `libbcc` declares that it provides `libbpfcc`.
That said, one should always test such a configuration in case of version incompatibilities.

**iovisor packages (Upstream Stable and Signed Packages)**

```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```
(replace `xenial` with `artful` or `bionic` as appropriate). Tools will be installed under /usr/share/bcc/tools.

**Upstream Nightly Packages**

```bash
echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```
(replace `xenial` with `artful` or `bionic` as appropriate)

## Fedora - Binary

### Fedora 30 and newer

As of Fedora 30, bcc binaries are available in the standard repository.
You can install them via

```bash
sudo dnf install bcc
```

**Note**: if you keep getting `Failed to load program: Operation not permitted` when
trying to run the `hello_world.py` example as root then you might need to lift
the so-called kernel lockdown (cf.
[FAQ](https://github.com/iovisor/bcc/blob/c00d10d4552f647491395e326d2e4400f3a0b6c5/FAQ.txt#L24),
[background article](https://gehrcke.de/2019/09/running-an-ebpf-program-may-require-lifting-the-kernel-lockdown)).


### Fedora 29 and older

Ensure that you are running a 4.2+ kernel with `uname -r`. If not, install a 4.2+ kernel from
http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug, for example:

```bash
sudo dnf config-manager --add-repo=http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug/fedora-rawhide-kernel-nodebug.repo
sudo dnf update
# reboot
```

**Nightly Packages**

Nightly bcc binary packages for Fedora 25, 26, 27, and 28 are hosted at
`https://repo.iovisor.org/yum/nightly/f{25,26,27}`.

To install:
```bash
echo -e '[iovisor]\nbaseurl=https://repo.iovisor.org/yum/nightly/f27/$basearch\nenabled=1\ngpgcheck=0' | sudo tee /etc/yum.repos.d/iovisor.repo
sudo dnf install bcc-tools kernel-headers kernel-devel
```

**Stable and Signed Packages**

Stable bcc binary packages for Fedora 25, 26, 27, and 28 are hosted at
`https://repo.iovisor.org/yum/main/f{25,26,27}`.

```bash
echo -e '[iovisor]\nbaseurl=https://repo.iovisor.org/yum/main/f27/$basearch\nenabled=1' | sudo tee /etc/yum.repos.d/iovisor.repo
sudo dnf install bcc-tools kernel-devel-$(uname -r) kernel-headers-$(uname -r)
```

## Arch - AUR

Upgrade the kernel to minimum 4.3.1-1 first; the ```CONFIG_BPF_SYSCALL=y``` configuration was not added until [this kernel release](https://bugs.archlinux.org/task/47008).

Install these packages using any AUR helper such as [pacaur](https://aur.archlinux.org/packages/pacaur), [yaourt](https://aur.archlinux.org/packages/yaourt), [cower](https://aur.archlinux.org/packages/cower), etc.:
```
bcc bcc-tools python-bcc
```
All build and install dependencies are listed [in the PKGBUILD](https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=bcc) and should install automatically.

## Gentoo - Portage

First of all, upgrade the kernel of your choice to a recent version. For example:
```
emerge sys-kernel/gentoo-sources
```
Then, configure the kernel enabling the features you need. Please consider the following as a starting point:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_NET_CLS_BPF=m
CONFIG_NET_ACT_BPF=m
CONFIG_BPF_JIT=y
CONFIG_BPF_EVENTS=y
```
Finally, you can install bcc with:
```
emerge dev-util/bcc
```
The appropriate dependencies (e.g., ```clang```, ```llvm``` with BPF backend) will be pulled automatically.

## openSUSE - Binary

For openSUSE Leap 42.2 (and later) and Tumbleweed, bcc is already included in the official repo. Just install
the packages with zypper.

```bash
sudo zypper ref
sudo zypper in bcc-tools bcc-examples
```

## RHEL - Binary

For RHEL 7.6, bcc is already included in the official yum repository as bcc-tools. As part of the install, the following dependencies are installed: bcc.x86_64 0:0.6.1-2.el7 ,llvm-private.x86_64 0:6.0.1-2.el7 ,python-bcc.x86_64 0:0.6.1-2.el7,python-netaddr.noarch 0:0.7.5-9.el7

```
yum install bcc-tools
```

## Amazon Linux 1 - Binary
Use case 1. Install BCC for latest kernel available in repo:
   Tested on Amazon Linux AMI release 2018.03 (kernel 4.14.88-72.73.amzn1.x86_64)
```
sudo yum update kernel
sudo yum install bcc
sudo reboot
```

Use case 2. Install BCC for your AMI's default kernel (no reboot required):
   Tested on Amazon Linux AMI release 2018.03 (kernel 4.14.77-70.59.amzn1.x86_64)
```
sudo yum install kernel-headers-$(uname -r | cut -d'.' -f1-5)
sudo yum install kernel-devel-$(uname -r | cut -d'.' -f1-5)
sudo yum install bcc
```

## Amazon Linux 2 - Binary
Use case 1. Install BCC for your AMI's default kernel (no reboot required):
   Tested on Amazon Linux AMI release 2020.03 (kernel 4.14.154-128.181.amzn2.x86_64)
```
sudo amazon-linux-extras enable BCC
sudo yum install kernel-devel-$(uname -r)
sudo yum install bcc
```

## Alpine - Binary

As of Alpine 3.11, bcc binaries are available in the community repository:

```
sudo apk add bcc-tools bcc-doc
```

The tools are installed in `/usr/share/bcc/tools`.

**Python Compatibility**

The binary packages include bindings for Python 3 only. The Python-based tools assume that a `python` binary is available at `/usr/bin/python`, but that may not be true on recent versions of Alpine. If you encounter errors like `<tool-name>: not found`, you can try creating a symlink to the Python 3.x binary like so:

```
sudo ln -s $(which python3) /usr/bin/python
```

**Containers**

Alpine Linux is often used as a base system for containers. `bcc` can be used in such an environment by launching the container in privileged mode with kernel modules available through bind mounts:

```
sudo docker run --rm -it --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /sys:/sys:ro \
  -v /usr/src:/usr/src:ro \
  alpine:3.12
```

# Source

## libbpf Submodule

Since release v0.10.0, bcc starts to leverage libbpf repo (https://github.com/libbpf/libbpf)
to provide wrapper functions to the kernel for bpf syscalls, uapi headers bpf.h/btf.h etc.
Unfortunately, the default github release source code does not contain libbpf submodule
source code and this will cause build issues.

To alleviate this problem, starting at release v0.11.0, source code with corresponding
libbpf submodule codes will be released as well. See https://github.com/iovisor/bcc/releases.

## Debian - Source
### Jessie
#### Repositories

The automated tests that run as part of the build process require `netperf`.  Since netperf's license is not "certified"
as an open-source license, it is in Debian's `non-free` repository.

`/etc/apt/sources.list` should include the `non-free` repository and look something like this:

```
deb http://httpredir.debian.org/debian/ jessie main non-free
deb-src http://httpredir.debian.org/debian/ jessie main non-free

deb http://security.debian.org/ jessie/updates main non-free
deb-src http://security.debian.org/ jessie/updates main non-free

# wheezy-updates, previously known as 'volatile'
deb http://ftp.us.debian.org/debian/ jessie-updates main non-free
deb-src http://ftp.us.debian.org/debian/ jessie-updates main non-free
```

BCC also requires kernel version 4.1 or above.  Those kernels are available in the `jessie-backports` repository.  To
add the `jessie-backports` repository to your system create the file `/etc/apt/sources.list.d/jessie-backports.list`
with the following contents:

```
deb http://httpredir.debian.org/debian jessie-backports main
deb-src http://httpredir.debian.org/debian jessie-backports main
```

#### Install Build Dependencies

Note, check for the latest `linux-image-4.x` version in `jessie-backports` before proceeding.  Also, have a look at the
`Build-Depends:` section in `debian/control` file.

```
# Before you begin
apt-get update

# Update kernel and linux-base package
apt-get -t jessie-backports install linux-base linux-image-4.9.0-0.bpo.2-amd64 linux-headers-4.9.0-0.bpo.2-amd64

# BCC build dependencies:
apt-get install debhelper cmake libllvm3.8 llvm-3.8-dev libclang-3.8-dev \
  libelf-dev bison flex libedit-dev clang-format-3.8 python python-netaddr \
  python-pyroute2 luajit libluajit-5.1-dev arping iperf netperf ethtool \
  devscripts zlib1g-dev libfl-dev
```

#### Sudo

Adding eBPF probes to the kernel and removing probes from it requires root privileges.  For the build to complete
successfully, you must build from an account with `sudo` access.  (You may also build as root, but it is bad style.)

`/etc/sudoers` or `/etc/sudoers.d/build-user` should contain

```
build-user ALL = (ALL) NOPASSWD: ALL
```

or

```
build-user ALL = (ALL) ALL
```

If using the latter sudoers configuration, please keep an eye out for sudo's password prompt while the build is running.

#### Build

```
cd <preferred development directory>
git clone https://github.com/iovisor/bcc.git
cd bcc
debuild -b -uc -us
```

#### Install

```
cd ..
sudo dpkg -i *bcc*.deb
```

## Ubuntu - Source

To build the toolchain from source, one needs:
* LLVM 3.7.1 or newer, compiled with BPF support (default=on)
* Clang, built from the same tree as LLVM
* cmake (>=3.1), gcc (>=4.7), flex, bison
* LuaJIT, if you want Lua support

### Install build dependencies
```
# Trusty (14.04 LTS) and older
VER=trusty
echo "deb http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main
deb-src http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main" | \
  sudo tee /etc/apt/sources.list.d/llvm.list
wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update

# For Bionic (18.04 LTS)
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev

# For Eoan (19.10)
sudo apt install -y bison build-essential cmake flex git libedit-dev \
  libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev

# For other versions
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev libelf-dev

# For Lua support
sudo apt-get -y install luajit luajit-5.1-dev
```

### Install and compile BCC

```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

## Fedora - Source

### Install build dependencies

```
sudo dnf install -y bison cmake ethtool flex git iperf libstdc++-static \
  python-netaddr python-pip gcc gcc-c++ make zlib-devel \
  elfutils-libelf-devel
sudo dnf install -y luajit luajit-devel  # for Lua support
sudo dnf install -y \
  http://repo.iovisor.org/yum/extra/mageia/cauldron/x86_64/netperf-2.7.0-1.mga6.x86_64.rpm
sudo pip install pyroute2
```

### Install binary clang

```
# FC22
wget http://llvm.org/releases/3.7.1/clang+llvm-3.7.1-x86_64-fedora22.tar.xz
sudo tar xf clang+llvm-3.7.1-x86_64-fedora22.tar.xz -C /usr/local --strip 1

# FC23
wget http://llvm.org/releases/3.9.0/clang+llvm-3.9.0-x86_64-fedora23.tar.xz
sudo tar xf clang+llvm-3.9.0-x86_64-fedora23.tar.xz -C /usr/local --strip 1

# FC24 and FC25
sudo dnf install -y clang clang-devel llvm llvm-devel llvm-static ncurses-devel
```

### Install and compile BCC
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
```

## openSUSE - Source

### Install build dependencies

```
sudo zypper in bison cmake flex gcc gcc-c++ git libelf-devel libstdc++-devel \
  llvm-devel clang-devel pkg-config python-devel python-setuptools python3-devel \
  python3-setuptools
sudo zypper in luajit-devel       # for lua support in openSUSE Leap 42.2 or later
sudo zypper in lua51-luajit-devel # for lua support in openSUSE Tumbleweed
```

### Install and compile BCC
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake -DLUAJIT_INCLUDE_DIR=`pkg-config --variable=includedir luajit` \ # for lua support
      ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

## Centos - Source

For Centos 7.6 only

### Install build dependencies

```
sudo yum install -y epel-release
sudo yum update -y
sudo yum groupinstall -y "Development tools"
sudo yum install -y elfutils-libelf-devel cmake3 git bison flex ncurses-devel
sudo yum install -y luajit luajit-devel  # for Lua support
```

### Install and compile LLVM

You could compile LLVM from source code

```
curl  -LO  http://releases.llvm.org/7.0.1/llvm-7.0.1.src.tar.xz
curl  -LO  http://releases.llvm.org/7.0.1/cfe-7.0.1.src.tar.xz
tar -xf cfe-7.0.1.src.tar.xz
tar -xf llvm-7.0.1.src.tar.xz

mkdir clang-build
mkdir llvm-build

cd llvm-build
cmake3 -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_BUILD_TYPE=Release ../llvm-7.0.1.src
make
sudo make install

cd ../clang-build
cmake3 -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_BUILD_TYPE=Release ../cfe-7.0.1.src
make
sudo make install
cd ..
```

or install from centos-release-scl

```
yum install -y centos-release-scl
yum-config-manager --enable rhel-server-rhscl-7-rpms
yum install -y devtoolset-7 llvm-toolset-7 llvm-toolset-7-llvm-devel llvm-toolset-7-llvm-static llvm-toolset-7-clang-devel
source scl_source enable devtoolset-7 llvm-toolset-7
```

For permanently enable scl environment, please check https://access.redhat.com/solutions/527703.

### Install and compile BCC

```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake3 ..
make
sudo make install
```

## Amazon Linux 1 - Source

Tested on Amazon Linux AMI release 2018.03 (kernel 4.14.47-56.37.amzn1.x86_64)

### Install packages required for building
```
# enable epel to get iperf, luajit, luajit-devel, cmake3 (cmake3 is required to support c++11)
sudo yum-config-manager --enable epel

sudo yum install -y bison cmake3 ethtool flex git iperf libstdc++-static python-netaddr gcc gcc-c++ make zlib-devel elfutils-libelf-devel
sudo yum install -y luajit luajit-devel
sudo yum install -y http://repo.iovisor.org/yum/extra/mageia/cauldron/x86_64/netperf-2.7.0-1.mga6.x86_64.rpm
sudo pip install pyroute2
sudo yum install -y ncurses-devel
```

### Install clang 3.7.1 pre-built binaries
```
wget http://releases.llvm.org/3.7.1/clang+llvm-3.7.1-x86_64-fedora22.tar.xz
tar xf clang*
(cd clang* && sudo cp -R * /usr/local/)
```

### Build bcc
```
git clone https://github.com/iovisor/bcc.git
pushd .
mkdir bcc/build; cd bcc/build
cmake3 ..
time make
sudo make install
popd
```

### Setup required to run the tools
```
sudo yum -y install kernel-devel-$(uname -r)
sudo mount -t debugfs debugfs /sys/kernel/debug
```

### Test
```
sudo /usr/share/bcc/tools/execsnoop
```

## Amazon Linux 2 - Source

```
# enable epel to get iperf, luajit, luajit-devel, cmake3 (cmake3 is required to support c++11)
sudo yum-config-manager --enable epel

sudo yum install -y bison cmake3 ethtool flex git iperf libstdc++-static python-netaddr gcc gcc-c++ make zlib-devel elfutils-libelf-devel
sudo yum install -y luajit luajit-devel
sudo yum install -y http://repo.iovisor.org/yum/extra/mageia/cauldron/x86_64/netperf-2.7.0-1.mga6.x86_64.rpm
sudo pip install pyroute2
sudo yum install -y ncurses-devel
```

### Install clang
```
yum install -y clang llvm llvm-devel llvm-static clang-devel clang-libs
```

### Build bcc
```
git clone https://github.com/iovisor/bcc.git
pushd .
mkdir bcc/build; cd bcc/build
cmake3 ..
time make
sudo make install
popd
```

### Setup required to run the tools
```
sudo yum -y install kernel-devel-$(uname -r)
sudo mount -t debugfs debugfs /sys/kernel/debug
```

### Test
```
sudo /usr/share/bcc/tools/execsnoop
```

## Alpine - Source

### Install packages required for building

```
sudo apk add tar git build-base iperf linux-headers llvm10-dev llvm10-static \
  clang-dev clang-static cmake python3 flex-dev bison luajit-dev elfutils-dev \
  zlib-dev
```

### Build bcc

```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
# python2 can be substituted here, depending on your environment
cmake -DPYTHON_CMD=python3 ..
make && sudo make install

# Optional, but needed if you don't have /usr/bin/python on your system
ln -s $(which python3) /usr/bin/python
```

### Test

```
sudo /usr/share/bcc/tools/execsnoop
```

# Older Instructions

## Build LLVM and Clang development libs

```
git clone https://github.com/llvm/llvm-project.git
mkdir -p llvm-project/llvm/build/install
cd llvm-project/llvm/build
cmake -G "Ninja" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DLLVM_ENABLE_PROJECTS="clang" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/install ..
ninja && ninja install
export PATH=$PWD/install/bin:$PATH
```
