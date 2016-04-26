%define debug_package %{nil}

Name:           bcc
Version:        @REVISION@
Release:        @GIT_REV_COUNT@
Summary:        BPF Compiler Collection (BCC)

Group:          Development/Languages
License:        ASL 2.0
URL:            https://github.com/iovisor/bcc
Source0:        bcc.tar.gz

BuildArch:      x86_64
BuildRequires:  bison, cmake >= 2.8.7, flex, gcc, gcc-c++, python2-devel

%description
Python bindings for BPF Compiler Collection (BCC). Control a BPF program from
userspace.


%prep
%setup -n bcc

%build

mkdir build
pushd build
cmake .. -DREVISION_LAST=%{version} -DREVISION=%{version} -DCMAKE_INSTALL_PREFIX=/usr
make %{?_smp_mflags}
popd

%install
pushd build
make install/strip DESTDIR=%{buildroot}

%changelog
* Mon Apr 04 2016 Vicent Marti <vicent@github.com> - 0.1.4-1
- Add bcc-lua package

* Sun Nov 29 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.3-1
- Add bcc-tools package

* Mon Oct 12 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.2-1
- Add better version numbering into libbcc.so

* Fri Jul 03 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.1-2
- Initial RPM Release

%package -n libbcc
Summary: Shared Library for BPF Compiler Collection (BCC)
%description -n libbcc
Shared Library for BPF Compiler Collection (BCC)

%package -n libbcc-examples
Summary: Examples for BPF Compiler Collection (BCC)
Requires: libbcc
%description -n libbcc-examples
Examples for BPF Compiler Collection (BCC)

%package -n python-bcc
Summary: Python bindings for BPF Compiler Collection (BCC)
Requires: libbcc
%description -n python-bcc
Python bindings for BPF Compiler Collection (BCC)

%package -n bcc-tools
Summary: Command line tools for BPF Compiler Collection (BCC)
Requires: python-bcc
%description -n bcc-tools
Command line tools for BPF Compiler Collection (BCC)

%package -n bcc-lua
Summary: Standalone tool to run BCC tracers written in Lua
Requires: libbcc
%description -n bcc-lua
Standalone tool to run BCC tracers written in Lua

%files -n python-bcc
%{python_sitelib}/bcc*

%files -n libbcc
/usr/lib64/*
/usr/include/bcc/*

%files -n libbcc-examples
/usr/share/bcc/examples/*
%exclude /usr/share/bcc/examples/*.pyc
%exclude /usr/share/bcc/examples/*.pyo
%exclude /usr/share/bcc/examples/*/*.pyc
%exclude /usr/share/bcc/examples/*/*.pyo
%exclude /usr/share/bcc/examples/*/*/*.pyc
%exclude /usr/share/bcc/examples/*/*/*.pyo

%files -n bcc-tools
/usr/share/bcc/tools/*
/usr/share/bcc/man/*

%files -n bcc-lua
/usr/bin/bcc-lua
