%bcond_with local_clang_static
#lua jit not available for some architectures
%ifarch ppc64 aarch64 ppc64le
%{!?with_lua: %global with_lua 0}
%else
%{!?with_lua: %global with_lua 1}
%endif

# use --with shared to only link against libLLVM.so
%if 0%{?fedora} >= 28 || 0%{?rhel} > 7
%bcond_without llvm_shared
%else
%bcond_with llvm_shared
%endif

# Build python3 support for distributions that have it
%if 0%{?fedora} >= 28 || 0%{?rhel} > 7
%bcond_without python3
%else
%bcond_with python3
%endif

%if %{with python3}
%global __python %{__python3}
%global python_bcc python3-bcc
%global python_cmds python2;python3
%else
%global __python %{__python2}
%global python_bcc python2-bcc
%global python_cmds python2
%endif

%define debug_package %{nil}

Name:           bcc
Version:        @REVISION@
Release:        @GIT_REV_COUNT@
Summary:        BPF Compiler Collection (BCC)

Group:          Development/Languages
License:        ASL 2.0
URL:            https://github.com/iovisor/bcc
Source0:        bcc.tar.gz

ExclusiveArch: x86_64 ppc64 aarch64 ppc64le
BuildRequires: bison cmake >= 2.8.7 flex make
BuildRequires: gcc gcc-c++ python2-devel elfutils-libelf-devel-static
%if %{with python3}
BuildRequires: python3-devel
%endif
%if %{with_lua}
BuildRequires: luajit luajit-devel
%endif
%if %{without local_clang_static}
BuildRequires: llvm-devel
BuildRequires: clang-devel
%if %{without llvm_shared}
BuildRequires: llvm-static
%endif
%endif
BuildRequires: pkgconfig ncurses-devel

%description
Python bindings for BPF Compiler Collection (BCC). Control a BPF program from
userspace.

%if %{with_lua}
%global lua_include `pkg-config --variable=includedir luajit`
%global lua_libs `pkg-config --variable=libdir luajit`/lib`pkg-config --variable=libname luajit`.so
%global lua_config -DLUAJIT_INCLUDE_DIR=%{lua_include} -DLUAJIT_LIBRARIES=%{lua_libs}
%endif

%prep
%setup -q -n bcc

%build

mkdir build
pushd build
cmake .. -DREVISION_LAST=%{version} -DREVISION=%{version} \
      -DCMAKE_INSTALL_PREFIX=/usr \
      %{?lua_config} \
      -DPYTHON_CMD="%{python_cmds}" \
      %{?with_llvm_shared:-DENABLE_LLVM_SHARED=1}
make %{?_smp_mflags}
popd

%install
pushd build
make install/strip DESTDIR=%{buildroot}
# mangle shebangs
find %{buildroot}/usr/share/bcc/{tools,examples} -type f -exec \
    sed -i -e '1 s|^#!/usr/bin/python$|#!'%{__python}'|' \
           -e '1 s|^#!/usr/bin/env python$|#!'%{__python}'|' {} \;

%package -n libbcc
Summary: Shared Library for BPF Compiler Collection (BCC)
Requires: elfutils-libelf
%description -n libbcc
Shared Library for BPF Compiler Collection (BCC)

%package -n python2-bcc
Summary: Python2 bindings for BPF Compiler Collection (BCC)
Requires: libbcc = %{version}-%{release}
%{?python_provide:%python_provide python2-bcc}
%description -n python2-bcc
Python bindings for BPF Compiler Collection (BCC)

%if %{with python3}
%package -n python3-bcc
Summary: Python3 bindings for BPF Compiler Collection (BCC)
Requires: libbcc = %{version}-%{release}
%{?python_provide:%python_provide python3-bcc}
%description -n python3-bcc
Python bindings for BPF Compiler Collection (BCC)
%endif

%if %{with_lua}
%package -n bcc-lua
Summary: Standalone tool to run BCC tracers written in Lua
Requires: libbcc = %{version}-%{release}
%description -n bcc-lua
Standalone tool to run BCC tracers written in Lua
%endif

%package -n libbcc-examples
Summary: Examples for BPF Compiler Collection (BCC)
Requires: %{python_bcc} = %{version}-%{release}
%if %{with_lua}
Requires: bcc-lua = %{version}-%{release}
%endif
%description -n libbcc-examples
Examples for BPF Compiler Collection (BCC)

%package -n bcc-tools
Summary: Command line tools for BPF Compiler Collection (BCC)
Requires: %{python_bcc} = %{version}-%{release}
%description -n bcc-tools
Command line tools for BPF Compiler Collection (BCC)

%files -n libbcc
/usr/lib64/*
/usr/include/bcc/*

%files -n python2-bcc
%{python2_sitelib}/bcc*

%if %{with python3}
%files -n python3-bcc
%{python3_sitelib}/bcc*
%endif

%if %{with_lua}
%files -n bcc-lua
/usr/bin/bcc-lua
%endif

%files -n libbcc-examples
/usr/share/bcc/examples/*
%exclude /usr/share/bcc/examples/*.pyc
%exclude /usr/share/bcc/examples/*.pyo
%exclude /usr/share/bcc/examples/*/*.pyc
%exclude /usr/share/bcc/examples/*/*.pyo
%exclude /usr/share/bcc/examples/*/*/*.pyc
%exclude /usr/share/bcc/examples/*/*/*.pyo

%files -n bcc-tools
/usr/share/bcc/introspection/*
/usr/share/bcc/tools/*
/usr/share/bcc/man/*

%post -n libbcc -p /sbin/ldconfig

%postun -n libbcc -p /sbin/ldconfig

%changelog
* Wed Jul 18 2018 Brenden Blanco <bblanco@gmail.com> - 0.6.0-1
- Make python3 the default when possible
- Add with llvm_shared conditional
- Add python2/python3 package targets

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
