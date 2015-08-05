# Ubuntu - Binary

Install a 4.2+ kernel from http://kernel.ubuntu.com/~kernel-ppa/mainline,
for example:

```bash
VER=4.2.0-040200rc5
REL=201508030228
PREFIX=http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.2-rc5-unstable
wget ${PREFIX}/linux-headers-${VER}-generic_${VER}.${REL}_amd64.deb
wget ${PREFIX}/linux-headers-${VER}_${VER}.${REL}_all.deb
wget ${PREFIX}/linux-image-${VER}-generic_${VER}.${REL}_amd64.deb
sudo dpkg -i linux-*${VER}.${REL}*.deb
# reboot
```

Tagged binary packages are built for Ubuntu Trusty (14.04) and hosted at
http://52.8.15.63/apt/.

To install:
```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
echo "deb http://52.8.15.63/apt trusty main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install libbcc
```

Test it:
`sudo python /usr/share/bcc/examples/hello_world.py`

(Optional) Install pyroute2 for additional networking features
```bash
git clone https://github.com/svinota/pyroute2
cd pyroute2; sudo make install
sudo python /usr/share/bcc/examples/simple_tc.py
```

# Fedora - Docker edition

The build dependencies are captured in a [Dockerfile](Dockerfile.fedora), the
output of which is a .rpm for easy installation. This version takes longer since
LLVM needs to be compiled from source.

* Start with a recent Fedora install (tested with F22)
* Install a [>= 4.2 kernel](http://alt.fedoraproject.org/pub/alt/rawhide-kernel-nodebug/x86_64/)
  with headers
* Reboot
* Install [docker](https://docs.docker.com/installation/fedora/)
* Run the Dockerfile for Fedora - results in an installable .rpm
  * `git clone https://github.com/iovisor/bcc; cd bcc`
  * `docker build -t bcc -f Dockerfile.fedora .`
  * `docker run --rm -v /tmp:/mnt bcc sh -c "cp /root/bcc/build/*.rpm /mnt"`
  * `sudo rpm -ivh /tmp/libbcc*.rpm`
* Run the example
  * `sudo python /usr/share/bcc/examples/hello_world.py`

# Ubuntu - From source

To build the toolchain from source, one needs:
* LLVM 3.7 or newer, compiled with BPF support (default=on)
* Clang 3.7, built from the same tree as LLVM
* cmake, gcc (>=4.7), flex, bison

* Install build dependencies
  * `sudo apt-get -y install bison build-essential cmake flex git libedit-dev python zlib1g-dev`
* Build LLVM and Clang development libs
  * `git clone http://llvm.org/git/llvm.git`
  * `cd llvm/tools; git clone http://llvm.org/git/clang.git`
  * `cd ..; mkdir -p build/install; cd build`
  * `cmake -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/install ..`
  * `make -j4`
  * `make install`
  * `export PATH=$PWD/install/bin:$PATH`
* Install and compile BCC
  * `git clone https://github.com/iovisor/bcc.git`
  * `mkdir bcc/build; cd bcc/build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=/usr`
  * `make`
  * `sudo make install`

