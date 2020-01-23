# - Try to find libbpf
# Once done this will define
#
#  LIBBPF_FOUND            - system has libbpf
#  LIBBPF_INCLUDE_DIR      - the libbpf include directory
#  LIBBPF_STATIC_LIBRARIES - the libbpf source directory
#  LIBBPF_LIBRARIES        - link these to use libbpf

#if (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIR AND LIBBPF_STATIC_LIBRARIES)
#  set (LibBpf_FIND_QUIETLY TRUE)
#endif (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIR AND LIBBPF_STATIC_LIBRARIES)

# You'll need following packages to be installed (Fedora names):
# libbpf
# libbpf-static
# libbpf-devel

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

find_library (LIBBPF_STATIC_LIBRARIES
  NAMES
    libbpf.a
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

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
  LIBBPF_STATIC_LIBRARIES
  LIBBPF_INCLUDE_DIR)

mark_as_advanced(LIBBPF_INCLUDE_DIR LIBBPF_STATIC_LIBRARIES LIBBPF_LIBRARIES)
