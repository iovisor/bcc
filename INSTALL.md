# Installing BCC

* [Kernel Configuration](#kernel-configuration)
* [Packages](#packages)
  - [Ubuntu](#ubuntu-xenial---binary)
  - [Fedora](#fedora---binary)
  - [Arch](#arch---aur)
  - [Gentoo](#gentoo---portage)
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
echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
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
hosted at https://repo.iovisor.org/apt/.

To install:
```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
echo "deb https://repo.iovisor.org/apt trusty main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install binutils bcc bcc-tools libbcc-examples python-bcc
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
`https://repo.iovisor.org/yum/nightly/f{23,24}`.

To install (change 'f23' to 'f24' for rawhide):
```bash
echo -e '[iovisor]\nbaseurl=https://repo.iovisor.org/yum/nightly/f23/$basearch\nenabled=1\ngpgcheck=0' | sudo tee /etc/yum.repos.d/iovisor.repo
sudo dnf install bcc-tools
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


# Source

## Debian - Source

```
ROUGH NOTES:

Add jessie-backports repo
Add non-free repo to sources.list
Install latest 4.x kernel and headers from jessie-backports
See updated control file for all package-build dependencies
Other required tooling: devscripts

debuild -b -uc -us

Re-running tests:
cd obj-x86_64-linux-gnu/
sudo /usr/bin/ctest --force-new-ctest-process -j1 -V

20: Test command: /home/mikep/bcc/obj-x86_64-linux-gnu/tests/wrapper.sh "py_uprobes" "sudo" "/home/mikep/bcc/tests/python/test_uprobes.py"  
20: Test timeout computed to be: 9.99988e+06
20: Python 2.7.9   
20: .Arena 0:
20: system bytes     =   13803520
20: in use bytes     =    2970096
20: Total (incl. mmap):
20: system bytes     =   14594048
20: in use bytes     =    3760624
20: max mmap regions =          4
20: max mmap bytes   =    1589248
20: F
20: ======================================================================
20: FAIL: test_simple_library (__main__.TestUprobes)
20: ----------------------------------------------------------------------
20: Traceback (most recent call last):
20:   File "/home/mikep/bcc/tests/python/test_uprobes.py", line 34, in test_simple_library
20:     self.assertEqual(b["stats"][ctypes.c_int(0)].value, 2)
20: AssertionError: 0L != 2

26: Test command: /home/mikep/bcc/obj-x86_64-linux-gnu/tests/wrapper.sh "lua_test_uprobes" "sudo" "/usr/bin/luajit" "test_uprobes.lua"
26: Test timeout computed to be: 9.99988e+06
26: Python 2.7.9   
26: Arena 0:
26: system bytes     =   12394496
26: in use bytes     =    1561664
26: Total (incl. mmap):
26: system bytes     =   12394496
26: in use bytes     =    1561664
26: max mmap regions =          4
26: max mmap bytes   =     999424
26: .F
26: Failed tests:  
26: -------------  
26: 1) TestUprobes.test_simple_library
26: test_uprobes.lua:38: expected: 2, actual: 0
26: stack traceback:
26:     test_uprobes.lua:38: in function 'TestUprobes.test_simple_library'
26:
26: Ran 2 tests in 0.141 seconds, 1 successes, 1 failures
26: Failed
26/28 Test #26: lua_test_uprobes .................***Failed    0.27 sec

test 28
      Start 28: lua_test_standalone

28: Test command: /home/mikep/bcc/tests/lua/test_standalone.sh
28: Test timeout computed to be: 9.99988e+06  
28: + cd src/lua
28: + [[ ! -x bcc-lua ]]
28: + ldd bcc-lua
28: + grep -q luajit
28: + rm -f libbcc.so probe.lua
28: + echo 'return function(BPF) print("Hello world") end'
28: + ./bcc-lua probe.lua
28: Hello world
28: + fail 'bcc-lua runs without libbcc.so'   
28: + echo 'test failed: bcc-lua runs without libbcc.so'
28: test failed: bcc-lua runs without libbcc.so
28: + exit 1
28/28 Test #28: lua_test_standalone ..............***Failed    0.01 sec
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
