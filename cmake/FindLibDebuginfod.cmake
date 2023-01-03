# - Try to find libdebuginfod
# Once done this will define
#
#  LIBDEBUGINFOD_FOUND - system has libdebuginfod
#  LIBDEBUGINFOD_INCLUDE_DIRS - the libdebuginfod include directory
#  LIBDEBUGINFOD_LIBRARIES - Link these to use libdebuginfod
#  LIBDEBUGINFOD_DEFINITIONS - Compiler switches required for using libdebuginfod


if (LIBDEBUGINFOD_LIBRARIES AND LIBDEBUGINFOD_INCLUDE_DIRS)
    set (LibDebuginfod_FIND_QUIETLY TRUE)
endif (LIBDEBUGINFOD_LIBRARIES AND LIBDEBUGINFOD_INCLUDE_DIRS)

find_path (LIBDEBUGINFOD_INCLUDE_DIRS
  NAMES
    elfutils/debuginfod.h
  PATHS
    /usr/include
    /usr/include/libelf
    /usr/include/elfutils
    /usr/local/include
    /usr/local/include/libelf
    /usr/local/include/elfutils
    /opt/local/include
    /opt/local/include/libelf
    /opt/local/include/elfutils
    /sw/include
    /sw/include/libelf
    /sw/include/elfutils
    ENV CPATH)

find_library (LIBDEBUGINFOD_LIBRARIES
  NAMES
    debuginfod
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBDEBUGINFOD_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibDebuginfod DEFAULT_MSG
  LIBDEBUGINFOD_LIBRARIES
  LIBDEBUGINFOD_INCLUDE_DIRS)

if (LIBDEBUGINFOD_FOUND AND ENABLE_LIBDEBUGINFOD)
  add_definitions(-DHAVE_LIBDEBUGINFOD)
endif (LIBDEBUGINFOD_FOUND AND ENABLE_LIBDEBUGINFOD)

mark_as_advanced(LIBDEBUGINFOD_INCLUDE_DIRS LIBDEBUGINFOD_LIBRARIES)
