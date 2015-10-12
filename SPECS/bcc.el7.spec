%define debug_package %{nil}
%define llvmver 3.7.0

Name:           bcc
Version:        0.1.7
Release:        1%{?dist}
Summary:        BPF Compiler Collection (BCC)

Group:          Development/Languages
License:        ASL 2.0
URL:            https://github.com/iovisor/bcc
Source0:        https://github.com/iovisor/bcc/archive/v%{version}.tar.gz
Source1:        http://llvm.org/releases/3.7.0/llvm-%{llvmver}.src.tar.xz
Source2:        http://llvm.org/releases/3.7.0/cfe-%{llvmver}.src.tar.xz

BuildArch:      x86_64
BuildRequires:  bison, cmake >= 2.8.7, flex, gcc, gcc-c++, python2-devel

%description
Python bindings for BPF Compiler Collection (BCC). Control a BPF program from
userspace.


%prep
%setup -T -b 1 -n llvm-%{llvmver}.src
mkdir tools/clang
tar -xvvJf %{_sourcedir}/cfe-%{llvmver}.src.tar.xz -C tools/clang --strip 1
%setup -D -n bcc-%{version}

%build

export LD_LIBRARY_PATH="%{_builddir}/usr/lib64"
export PATH="%{_builddir}/usr/bin":$PATH

# build llvm
pushd %{_builddir}/llvm-%{llvmver}.src
mkdir build
cd build
../configure --disable-assertions --enable-optimized --prefix="%{_builddir}/usr"
make -j`grep -c ^process /proc/cpuinfo`
make install
popd

mkdir build
pushd build
cmake .. -DREVISION=%{version} -DCMAKE_INSTALL_PREFIX=/usr
make -j`grep -c ^process /proc/cpuinfo`
popd

%install
pushd build
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
