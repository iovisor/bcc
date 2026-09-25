# - Try to find libgunwinder
# Once done this will define
#
#  LIBGUNWINDER_FOUND - system has libgunwinder
#  LIBGUNWINDER_TARGET - imported target for libgunwinder
#  LIBGUNWINDER_INCLUDE_DIRS - the libgunwinder include directory
#  LIBGUNWINDER_LIBRARIES - Link these to use libgunwinder
#  LIBGUNWINDER_STATIC_LIBRARIES - Link these for static consumers
#  LIBGUNWINDER_DEFINITIONS - Compiler switches required for using libgunwinder

if (LIBGUNWINDER_LIBRARIES AND LIBGUNWINDER_INCLUDE_DIRS)
    set (LibGunwinder_FIND_QUIETLY TRUE)
endif (LIBGUNWINDER_LIBRARIES AND LIBGUNWINDER_INCLUDE_DIRS)

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
  pkg_check_modules(PC_LIBGUNWINDER QUIET IMPORTED_TARGET libgunwinder)
endif (PKG_CONFIG_FOUND)

find_path (LIBGUNWINDER_INCLUDE_DIRS
  NAMES
    gunwinder/unwinder.h
  HINTS
    ${PC_LIBGUNWINDER_INCLUDEDIR}
    ${PC_LIBGUNWINDER_INCLUDE_DIRS}
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

find_library (LIBGUNWINDER_LIBRARIES
  NAMES
    gunwinder
  HINTS
    ${PC_LIBGUNWINDER_LIBDIR}
    ${PC_LIBGUNWINDER_LIBRARY_DIRS}
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

set(LIBGUNWINDER_DEFINITIONS ${PC_LIBGUNWINDER_CFLAGS_OTHER})
if (PC_LIBGUNWINDER_FOUND)
  set(LIBGUNWINDER_STATIC_LIBRARIES ${PC_LIBGUNWINDER_STATIC_LDFLAGS})
else()
  set(LIBGUNWINDER_STATIC_LIBRARIES ${LIBGUNWINDER_LIBRARIES})
endif()

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBGUNWINDER_FOUND to TRUE
# if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibGunwinder DEFAULT_MSG
  LIBGUNWINDER_LIBRARIES
  LIBGUNWINDER_INCLUDE_DIRS)

if (LIBGUNWINDER_FOUND AND NOT TARGET LibGunwinder::LibGunwinder)
  if (TARGET PkgConfig::PC_LIBGUNWINDER)
    set(_LIBGUNWINDER_PRIVATE_LINK_LIBRARIES "")
    if (LIBGUNWINDER_LIBRARIES MATCHES "\\.a$")
      set(_LIBGUNWINDER_PRIVATE_LINK_LIBRARIES ${PC_LIBGUNWINDER_STATIC_LDFLAGS})
    endif()
    add_library(LibGunwinder::LibGunwinder INTERFACE IMPORTED)
    set_property(TARGET LibGunwinder::LibGunwinder PROPERTY
      INTERFACE_LINK_LIBRARIES
        "PkgConfig::PC_LIBGUNWINDER;${_LIBGUNWINDER_PRIVATE_LINK_LIBRARIES}")
  else()
    add_library(LibGunwinder::LibGunwinder UNKNOWN IMPORTED)
    set_target_properties(LibGunwinder::LibGunwinder PROPERTIES
      IMPORTED_LOCATION "${LIBGUNWINDER_LIBRARIES}"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBGUNWINDER_INCLUDE_DIRS}"
      INTERFACE_COMPILE_OPTIONS "${LIBGUNWINDER_DEFINITIONS}")
  endif()
endif()

if (LIBGUNWINDER_FOUND)
  set(LIBGUNWINDER_TARGET LibGunwinder::LibGunwinder)
endif()

mark_as_advanced(LIBGUNWINDER_INCLUDE_DIRS LIBGUNWINDER_LIBRARIES LIBGUNWINDER_STATIC_LIBRARIES)
