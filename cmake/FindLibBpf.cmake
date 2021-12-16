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
if(LIBBPF_LIBRARIES)
list(APPEND PATHS LIBBPF_LIBRARIES)
endif()

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
if(LIBBPF_STATIC_LIBRARIES)
list(APPEND PATHS LIBBPF_STATIC_LIBRARIES)
endif()

if(LIBBPF_STATIC_LIBRARIES OR LIBBPF_LIBRARIES)
include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBpf "Please install the libbpf development package"
  ${PATHS}
  LIBBPF_INCLUDE_DIR)

mark_as_advanced(LIBBPF_INCLUDE_DIR ${PATHS})
else()
message(Please install the libbpf development package)
endif()
