%bcond_with local_clang_static
%define debug_package %{nil}

Name:           bcc
Version:        @REVISION@
Release:        @GIT_REV_COUNT@
Summary:        BPF Compiler Collection (BCC)

Group:          Development/Languages
License:        ASL 2.0
URL:            https://github.com/iovisor/bcc
Source0:        bcc.tar.gz

ExclusiveArch: x86_64
BuildRequires: bison cmake >= 2.8.7 flex make
BuildRequires: gcc gcc-c++ python2-devel elfutils-libelf-devel-static
BuildRequires: luajit luajit-devel
%if %{without local_clang_static}
BuildRequires: llvm-devel llvm-static
BuildRequires: clang-devel
%endif
BuildRequires: pkgconfig ncurses-devel

%description
Python bindings for BPF Compiler Collection (BCC). Control a BPF program from
userspace.


%prep
%setup -q -n bcc

%build

mkdir build
pushd build
cmake .. -DREVISION_LAST=%{version} -DREVISION=%{version} \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DLUAJIT_INCLUDE_DIR=`pkg-config --variable=includedir luajit` \
      -DLUAJIT_LIBRARIES=`pkg-config --variable=libdir luajit`/lib`pkg-config --variable=libname luajit`.so
make %{?_smp_mflags}
popd

%install
pushd build
make install/strip DESTDIR=%{buildroot}

%package -n libbcc
Summary: Shared Library for BPF Compiler Collection (BCC)
Requires: elfutils-libelf
%description -n libbcc
Shared Library for BPF Compiler Collection (BCC)

%package -n python-bcc
Summary: Python bindings for BPF Compiler Collection (BCC)
Requires: libbcc = %{version}-%{release}
%description -n python-bcc
Python bindings for BPF Compiler Collection (BCC)

%package -n bcc-lua
Summary: Standalone tool to run BCC tracers written in Lua
Requires: libbcc = %{version}-%{release}
%description -n bcc-lua
Standalone tool to run BCC tracers written in Lua

%package -n libbcc-examples
Summary: Examples for BPF Compiler Collection (BCC)
Requires: python-bcc = %{version}-%{release}
Requires: bcc-lua = %{version}-%{release}
%description -n libbcc-examples
Examples for BPF Compiler Collection (BCC)

%package -n bcc-tools
Summary: Command line tools for BPF Compiler Collection (BCC)
Requires: python-bcc = %{version}-%{release}
%description -n bcc-tools
Command line tools for BPF Compiler Collection (BCC)

%files -n libbcc
/usr/lib64/*
/usr/include/bcc/*

%files -n python-bcc
%{python_sitelib}/bcc*

%files -n bcc-lua
/usr/bin/bcc-lua

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

%post -n libbcc -p /sbin/ldconfig

%postun -n libbcc -p /sbin/ldconfig

%changelog
* Mon Nov 21 2016 William Cohen <wcohen@redhat.com> - 0.2.0-1
- Revise bcc.spec to address rpmlint issues and build properly in Fedora koji.

* Mon Apr 04 2016 Vicent Marti <vicent@github.com> - 0.1.4-1
- Add bcc-lua package

* Sun Nov 29 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.3-1
- Add bcc-tools package

* Mon Oct 12 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.2-1
- Add better version numbering into libbcc.so

* Fri Jul 03 2015 Brenden Blanco <bblanco@plumgrid.com> - 0.1.1-2
- Initial RPM Release
