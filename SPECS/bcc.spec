%define debug_package %{nil}

Name:           bcc
Version:        @REVISION@
Release:        1%{?dist}
Summary:        BPF Compiler Collection (BCC)

Group:          Development/Languages
License:        ASL 2.0
URL:            https://github.com/iovisor/bcc
Source0:        https://github.com/iovisor/bcc/archive/v%{version}.zip

BuildArch:      x86_64
BuildRequires:  python2-devel, cmake >= 2.8.7, flex, bison

%description
Python bindings for BPF Compiler Collection (BCC). Control a BPF program
from userspace.


%prep
%setup -n bcc-%{version}


%build
mkdir build
cd build
cmake .. -DREVISION=%{version} -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_C_COMPILER=/usr/local/bin/gcc -DCMAKE_CXX_COMPILER=/usr/local/bin/g++ -DCMAKE_PREFIX_PATH=/root/llvm/build
make -j8

%install
cd build
make install DESTDIR=%{buildroot}

%changelog
* Fri Jul 03 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.1-2
- Initial RPM Release

%package -n libbcc
Summary: Shared Library for BPF Compiler Collection (BCC)
%description -n libbcc
Shared Library for BPF Compiler Collection (BCC)

%package -n libbcc-examples
Summary: Examples for BPF Compiler Collection (BCC)
%description -n libbcc-examples
Examples for BPF Compiler Collection (BCC)

%package -n python-bpf
Summary: Python bindings for BPF Compiler Collection (BCC)
%description -n python-bpf
Python bindings for BPF Compiler Collection (BCC)

%files -n python-bpf
%{python_sitelib}/bpf*
%exclude %{python_sitelib}/*.egg-info
/usr/bin/bpf-run

%files -n libbcc
/usr/lib64/*
/usr/share/bcc/include/*
/usr/include/bcc/*

%files -n libbcc-examples
/usr/share/bcc/examples/*

#rpmbuild --define "_topdir `pwd`" -ba SPECS/bcc.spec
