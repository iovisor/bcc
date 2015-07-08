# Ubuntu - Docker edition

The build dependencies are captured in a [Dockerfile](Dockerfile.ubuntu), the
output of which is a .deb for easy installation.

* Start with a recent Ubuntu install (tested with 14.04 LTS)
* Install a [>= 4.2 kernel](http://kernel.ubuntu.com/~kernel-ppa/mainline/)
  with headers
* Reboot
* Install [docker](https://docs.docker.com/installation/ubuntulinux/)
  (`wget -qO- https://get.docker.com/ | sh`)
* Run the Dockerfile for Ubuntu - results in an installable .deb
  * `git clone https://github.com/iovisor/bcc; cd bcc`
  * `docker build -t bcc -f Dockerfile.ubuntu .`
  * `docker run --rm -v /tmp:/mnt bcc sh -c "cp /root/bcc/build/*.deb /mnt"`
  * `sudo dpkg -i /tmp/libbcc*.deb`
* Run the example
  * `sudo python /usr/share/bcc/examples/hello_world.py`

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

* Add the [LLVM binary repo](http://llvm.org/apt/) to your apt sources
  * `echo "deb http://llvm.org/apt/trusty/ llvm-toolchain-trusty main" | sudo tee /etc/apt/sources.list.d/llvm.list`
  * `wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -`
  * `sudo apt-get update`
* Install build dependencies
  * `sudo apt-get -y install bison build-essential cmake flex git libedit-dev python zlib1g-dev`
* Install LLVM and Clang development libs
  * `sudo apt-get -y install libllvm3.7 llvm-3.7-dev libclang-3.7-dev`
* Install and compile BCC
  * `git clone https://github.com/iovisor/bcc.git`
  * `mkdir bcc/build; cd bcc/build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=/usr`
  * `make`
  * `sudo make install`

