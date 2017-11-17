# Installing BCC

* [Kernel Configuration](#kernel-configuration)
* [Packages](#packages)
  - [Ubuntu](#ubuntu-xenial---binary)
  - [Fedora](#fedora---binary)
  - [Arch](#arch---aur)
  - [Gentoo](#gentoo---portage)
  - [openSUSE](#opensuse---binary)
* [Source](#source)
  - [Debian](#debian---source)
  - [Ubuntu](#ubuntu---source)
  - [Fedora](#fedora---source)
  - [openSUSE](#opensuse---source)
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

## Ubuntu Xenial - Binary

The stable and the nightly packages are built for Ubuntu Xenial (16.04). The steps are very straightforward, no need to upgrade the kernel or compile from source!

**Stable and Signed Packages**

```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
echo "deb https://repo.iovisor.org/apt/xenial xenial main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```

**Nightly Packages**

```bash
echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
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
hosted at https://repo.iovisor.org/apt/.

To install:
```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
echo "deb https://repo.iovisor.org/apt trusty main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install binutils bcc bcc-tools libbcc-examples python-bcc linux-headers-$(uname -r)
```

**Nightly Packages**

```bash
echo "deb [trusted=yes] https://repo.iovisor.org/apt/trusty trusty-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples
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
sudo python /usr/share/bcc/examples/networking/simple_tc.py
```

## Fedora - Binary

Ensure that you are running a 4.2+ kernel with `uname -r`. If not, install a 4.2+ kernel from
http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug, for example:

```bash
sudo dnf config-manager --add-repo=http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug/fedora-rawhide-kernel-nodebug.repo
sudo dnf update
# reboot
```

Nightly bcc binary packages for Fedora 23, 24, and 25 are hosted at
`https://repo.iovisor.org/yum/nightly/f{23,24,25}`.

To install:
```bash
echo -e '[iovisor]\nbaseurl=https://repo.iovisor.org/yum/nightly/f25/$basearch\nenabled=1\ngpgcheck=0' | sudo tee /etc/yum.repos.d/iovisor.repo
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
  devscripts zlib1g-dev
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
  python-netaddr python-pip gcc gcc-c++ make zlib-devel \
  elfutils-libelf-devel
sudo dnf install -y luajit luajit-devel  # for Lua support
sudo dnf install -y \
  http://pkgs.repoforge.org/netperf/netperf-2.6.0-1.el6.rf.x86_64.rpm
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
  llvm-devel pkg-config python-devel python-setuptools python3-devel \
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
