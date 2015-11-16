# Kernel requirements

## Requirements

In general, to use these features, a Linux kernel version 4.1 or newer is
required. In addition, the following flags should be set:

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

# Ubuntu - Binary

Install a 4.3+ kernel from http://kernel.ubuntu.com/~kernel-ppa/mainline,
for example:

```bash
VER=4.3.0-040300
PREFIX=http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.3-wily/
REL=201511020949
wget ${PREFIX}/linux-headers-${VER}-generic_${VER}.${REL}_amd64.deb
wget ${PREFIX}/linux-headers-${VER}_${VER}.${REL}_all.deb
wget ${PREFIX}/linux-image-${VER}-generic_${VER}.${REL}_amd64.deb
sudo dpkg -i linux-*${VER}.${REL}*.deb
# reboot
```

Update PREFIX to the latest date, and you can browse the files in the PREFIX url to find the REL number.

Tagged bcc binary packages are built for Ubuntu Trusty (14.04) and hosted at
http://52.8.15.63/apt/.

To install:
```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
echo "deb http://52.8.15.63/apt trusty main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install libbcc libbcc-examples python-bcc
```

Test it:
`sudo python /usr/share/bcc/examples/hello_world.py`
`sudo python /usr/share/bcc/examples/task_switch.py`

(Optional) Install pyroute2 for additional networking features
```bash
git clone https://github.com/svinota/pyroute2
cd pyroute2; sudo make install
sudo python /usr/share/bcc/examples/simple_tc.py
```

# Fedora - Binary

Install a 4.2+ kernel from
http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug, for example:

```bash
sudo wget http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug/fedora-rawhide-kernel-nodebug.repo -O /etc/yum.repos.d/fedora-rawhide-kernel-nodebug.repo
sudo dnf install -y kernel-core-4.2.0-1.fc24.x86_64 kernel-4.2.0-1.fc24.x86_64 kernel-devel-4.2.0-1.fc24.x86_64 kernel-modules-4.2.0-1.fc24.x86_64 kernel-headers-4.2.0-1.fc24.x86_64
# reboot
```

Tagged bcc binary packages are built for Fedora 22 and hosted at
http://52.8.15.63/yum/.

To install:
```bash
sudo wget http://52.8.15.63/yum/main/f22/iovisor.repo -O /etc/yum.repos.d/iovisor.repo
sudo dnf install -y libbcc libbcc-examples python-bcc
```

# Ubuntu - From source

To build the toolchain from source, one needs:
* LLVM 3.7 or newer, compiled with BPF support (default=on)
* Clang 3.7, built from the same tree as LLVM
* cmake, gcc (>=4.7), flex, bison

## Install build dependencies
```
VER=trusty
echo "deb http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main
deb-src http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main" | \
  sudo tee /etc/apt/sources.list.d/llvm.list
wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev
```

## Install and compile BCC
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

# Fedora - From source

## Install build dependencies

```
sudo dnf install -y bison cmake ethtool flex git iperf libstdc++-static \
  python-netaddr python-pip gcc gcc-c++ make zlib-devel
sudo dnf install -y \
  http://pkgs.repoforge.org/netperf/netperf-2.6.0-1.el6.rf.x86_64.rpm
sudo pip install pyroute2
```

## Install binary clang

```
wget http://llvm.org/releases/3.7.0/clang+llvm-3.7.0-x86_64-fedora22.tar.xz
sudo tar xf clang+llvm-3.7.0-x86_64-fedora22.tar.xz -C /usr/local --strip 1
```

## Install and compile BCC
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
# optional
export CC=/usr/local/bin/clang CXX=/usr/local/bin/clang++
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
```

# [Old] Build LLVM and Clang development libs
```
git clone http://llvm.org/git/llvm.git
cd llvm/tools; git clone http://llvm.org/git/clang.git
cd ..; mkdir -p build/install; cd build
cmake -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/install ..
make -j4
make install
export PATH=$PWD/install/bin:$PATH
```
