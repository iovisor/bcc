# - Try to find libbpf
# Once done this will define
#
#  LIBBPF_FOUND            - system has libbpf
#  LIBBPF_INCLUDE_DIR      - the libbpf include directory
#  LIBBPF_SOURCE_DIR       - the libbpf source directory
#  LIBBPF_LIBRARIES        - link these to use libbpf

#if (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIR AND LIBBPF_SOURCE_DIR)
#  set (LibBpf_FIND_QUIETLY TRUE)
#endif (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIR AND LIBBPF_SOURCE_DIR)

# You'll need following packages to be installed (Fedora names):
# libbpf
# libbpf-debugsource
# libbpf-devel
#
# Please note that you might need to enable updates-debuginfo repo
# for debugsource package like:
#   dnf install --enablerepo=updates-debuginfo libbpf-debugsource

find_path (LIBBPF_INCLUDE_DIR
  NAMES
    bpf/bpf.h
    bpf/btf.h
    bpf/libbpf.h

  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

file(GLOB libbpf_source_path /usr/src/debug/libbpf-*)

find_path (LIBBPF_SOURCE_DIR
  NAMES
    src/bpf.c
    src/bpf.h
    src/libbpf.c
    src/libbpf.h

  PATHS
    ${libbpf_source_path}
    ENV CPATH
)

find_library (LIBBPF_LIBRARIES
  NAMES
    bpf
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBpf "Please install the libbpf development package"
  LIBBPF_LIBRARIES
  LIBBPF_SOURCE_DIR
  LIBBPF_INCLUDE_DIR)

mark_as_advanced(LIBBPF_INCLUDE_DIR LIBBPF_SOURCE_DIR LIBBPF_LIBRARIES)
