# - Try to find liblzma
# Once done this will define
#
#  LIBLZMA_FOUND - system has liblzma
#  LIBLZMA_INCLUDE_DIRS - the liblzma include directory
#  LIBLZMA_LIBRARIES - Link these to use liblzma

if (LIBLZMA_LIBRARIES AND LIBLZMA_INCLUDE_DIRS)
    set (LibLzma_FIND_QUIETLY TRUE)
endif (LIBLZMA_LIBRARIES AND LIBLZMA_INCLUDE_DIRS)

find_path (LIBLZMA_INCLUDE_DIRS
  NAMES
    lzma.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

find_library (LIBLZMA_LIBRARIES
  NAMES
    lzma
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBLZMA_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibLzma DEFAULT_MSG
  LIBLZMA_LIBRARIES
  LIBLZMA_INCLUDE_DIRS)

if (LIBLZMA_FOUND)
  add_definitions(-DHAVE_LIBLZMA)
endif (LIBLZMA_FOUND)

mark_as_advanced(LIBLZMA_INCLUDE_DIRS LIBLZMA_LIBRARIES)
