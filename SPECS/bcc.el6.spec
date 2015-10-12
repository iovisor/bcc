# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

%define debug_package %{nil}
%define llvmver 3.7.0
%define gccver 5.1.0
%define pythonver 2.7.10

Name:           bcc
Version:        0.1.7
Release:        1%{?dist}
Summary:        BPF Compiler Collection (BCC)

Group:          Development/Languages
License:        ASL 2.0
URL:            https://github.com/iovisor/bcc
Source0:        https://github.com/iovisor/bcc/archive/v%{version}.tar.gz
Source1:        https://ftp.gnu.org/gnu/gcc/gcc-%{gccver}/gcc-%{gccver}.tar.gz
Source2:        https://www.python.org/ftp/python/%{pythonver}/Python-%{pythonver}.tgz
Source3:        http://llvm.org/releases/3.7.0/llvm-%{llvmver}.src.tar.xz
Source4:        http://llvm.org/releases/3.7.0/cfe-%{llvmver}.src.tar.xz

BuildArch:      x86_64
BuildRequires:  bison, bzip2, cmake >= 2.8.7, file, flex, gcc, gcc-c++, git, glibc-devel, glibc-utils, python2-devel, rpm-build, svn, tar, texinfo-tex, wget, zip, zlib-devel

%description
Python bindings for BPF Compiler Collection (BCC). Control a BPF program
from userspace.


%prep
%setup -T -b 1 -n gcc-%{gccver}
%setup -T -D -b 2 -n Python-%{pythonver}
%setup -T -D -b 3 -n llvm-%{llvmver}.src
mkdir tools/clang
tar -xvvJf %{_sourcedir}/cfe-%{llvmver}.src.tar.xz -C tools/clang --strip 1
%setup -D -n bcc-%{version}

%build

export LD_LIBRARY_PATH="%{_builddir}/usr/lib64"
export PATH="%{_builddir}/usr/bin":$PATH

# build gcc to bootstrap llvm build
pushd %{_builddir}/gcc-%{gccver}
./contrib/download_prerequisites
mkdir build
cd build
../configure --disable-multilib --prefix="%{_builddir}/usr"
make -j`grep -c ^process /proc/cpuinfo`
make install
popd

echo "%{_builddir}/usr/lib64" > /etc/ld.so.conf.d/usrLocalLib64.conf
ldconfig

# build newer python for llvm
pushd %{_builddir}/Python-%{pythonver}
./configure --prefix="%{_builddir}/usr"
make -j`grep -c ^process /proc/cpuinfo`
make install
popd

# build llvm with local gcc
pushd %{_builddir}/llvm-%{llvmver}.src
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="%{_builddir}/usr" -DCMAKE_C_COMPILER="%{_builddir}/usr/bin/gcc" -DCMAKE_CXX_COMPILER="%{_builddir}/usr/bin/g++" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86;BPF"
make -j`grep -c ^process /proc/cpuinfo`
make install
popd

rm /etc/ld.so.conf.d/usrLocalLib64.conf
ldconfig

mkdir build
cd build
cmake .. -DREVISION=%{version} -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_C_COMPILER="%{_builddir}/usr/bin/gcc" -DCMAKE_CXX_COMPILER="%{_builddir}/usr/bin/g++"
make -j`grep -c ^process /proc/cpuinfo`

%install
cd build
make install/strip DESTDIR=%{buildroot}

%changelog
* Fri Jul 03 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.1-2
- Initial RPM Release

%package -n libbcc
Summary: Shared Library for BPF Compiler Collection (BCC)
Requires: make, gcc
%description -n libbcc
Shared Library for BPF Compiler Collection (BCC)

%package -n libbcc-examples
Summary: Examples for BPF Compiler Collection (BCC)
%description -n libbcc-examples
Examples for BPF Compiler Collection (BCC)

%package -n python-bcc
Summary: Python bindings for BPF Compiler Collection (BCC)
%description -n python-bcc
Python bindings for BPF Compiler Collection (BCC)

%files -n python-bcc
%{python_sitelib}/bcc*
%exclude %{python_sitelib}/*.egg-info

%files -n libbcc
/usr/lib64/*
/usr/share/bcc/include/*
/usr/include/bcc/*

%files -n libbcc-examples
/usr/share/bcc/examples/*
