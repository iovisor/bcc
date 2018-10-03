# Installing BCC

* [Kernel Configuration](#kernel-configuration)
* [Packages](#packages)
  - [Ubuntu](#ubuntu---binary)
  - [Fedora](#fedora---binary)
  - [Arch](#arch---aur)
  - [Gentoo](#gentoo---portage)
  - [openSUSE](#opensuse---binary)
  - [RHEL](#redhat---binary)
* [Source](#source)
  - [Debian](#debian---source)
  - [Ubuntu](#ubuntu---source)
  - [Fedora](#fedora---source)
  - [openSUSE](#opensuse---source)
  - [Amazon Linux](#amazon-linux---source)
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

The stable and the nightly packages are built for Ubuntu Xenial (16.04), Ubuntu Artful (17.10) and Ubuntu Bionic (18.04). The steps are very straightforward, no need to upgrade the kernel or compile from source!

**Stable and Signed Packages**

```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/xenial xenial main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```
(replace `xenial` with `artful` or `bionic` as appropriate)

**Nightly Packages**

```bash
echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```
(replace `xenial` with `artful` or `bionic` as appropriate)

## Fedora - Binary

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
bcc bcc-tools python-bcc python2-bcc
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

For Redhat 7.6 (Beta) bcc is already included in the official yum repository as bcc-tools. As part of the install the following dependencies are installed: bcc.x86_64 0:0.6.0-3.el7 ,llvm-private.x86_64 0:6.0.1-2.el7 ,python-bcc.x86_64 0:0.6.0-3.el7,python-netaddr.noarch 0:0.7.5-9.el7

```
yum install bcc-tools
```

# Source

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
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
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
cmake -DCMAKE_INSTALL_PREFIX=/usr \
      -DLUAJIT_INCLUDE_DIR=`pkg-config --variable=includedir luajit` \ # for lua support
      ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

## Amazon Linux - Source

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
cmake3 .. -DCMAKE_INSTALL_PREFIX=/usr
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
