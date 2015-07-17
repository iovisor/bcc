# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
cmake_minimum_required(VERSION 2.8.7)

project(bcc)
set(CMAKE_BUILD_TYPE Release)

enable_testing()

include(scripts/GetGitRevisionDescription.cmake)
get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)
if(LIB64)
  set(LIBSUFFIX 64)
endif()

if(NOT PYTHON_ONLY)
find_package(BISON)
find_package(FLEX)

if(EXISTS /usr/share/llvm-3.7/cmake/LLVMConfig.cmake)
  # Likely we have a standard installation with pre-built packages
  set(BASE_LLVM_INSTALL_DIR "/usr/lib/llvm-3.7")
  set(LLVM_INCLUDE_DIRS "${BASE_LLVM_INSTALL_DIR}/include")
  set(LLVM_DEFINITIONS "-D__STDC_LIMIT_MACROS;-D__STDC_CONSTANT_MACROS")
  set(LLVM_LIBRARY_DIRS "${BASE_LLVM_INSTALL_DIR}/lib")
  set(FIND_LLVM_PACKAGE_CALLED 0)
else()
  find_package(LLVM)
  set(FIND_LLVM_PACKAGE_CALLED 1)
endif()

# clang is linked as a library, but the library path searching is
# primitively supported, unlike libLLVM
set(CLANG_SEARCH "/opt/local/llvm/lib;/usr/lib/llvm-3.7/lib;${LLVM_LIBRARY_DIRS}")
find_library(libclangAnalysis NAMES clangAnalysis HINTS ${CLANG_SEARCH})
find_library(libclangAST NAMES clangAST HINTS ${CLANG_SEARCH})
find_library(libclangBasic NAMES clangBasic HINTS ${CLANG_SEARCH})
find_library(libclangCodeGen NAMES clangCodeGen HINTS ${CLANG_SEARCH})
find_library(libclangDriver NAMES clangDriver HINTS ${CLANG_SEARCH})
find_library(libclangEdit NAMES clangEdit HINTS ${CLANG_SEARCH})
find_library(libclangFrontend NAMES clangFrontend HINTS ${CLANG_SEARCH})
find_library(libclangLex NAMES clangLex HINTS ${CLANG_SEARCH})
find_library(libclangParse NAMES clangParse HINTS ${CLANG_SEARCH})
find_library(libclangRewrite NAMES clangRewrite HINTS ${CLANG_SEARCH})
find_library(libclangSema NAMES clangSema HINTS ${CLANG_SEARCH})
find_library(libclangSerialization NAMES clangSerialization HINTS ${CLANG_SEARCH})
if(libclangBasic STREQUAL "libclangBasic-NOTFOUND")
  message(FATAL_ERROR "Unable to find clang libraries")
endif()
FOREACH(DIR ${LLVM_INCLUDE_DIRS})
  include_directories("${DIR}/../tools/clang/include")
ENDFOREACH()

if(FIND_LLVM_PACKAGE_CALLED EQUAL 0)
  # LLVMExports.cmake and LLVMExports-release.cmake are adapted from a local
  # llvm cmake build with -DBUILD_SHARED_LIBS=OFF
  set(_IMPORT_PREFIX "${BASE_LLVM_INSTALL_DIR}")
  include("LLVMExports.cmake")
endif()

set(CMAKE_C_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")
endif()

add_subdirectory(scripts)
add_subdirectory(examples)
add_subdirectory(src)
add_subdirectory(tests)

set(CPACK_PACKAGE_NAME "libbcc")
set(CPACK_PACKAGE_VERSION "${REVISION}")
set(CPACK_PACKAGE_CONTACT "Brenden Blanco <bblanco@plumgrid.com")
if(EXISTS "/etc/redhat-release")
  set(CPACK_GENERATOR "RPM")
else()
  set(CPACK_GENERATOR "DEB")
endif()
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libstdc++6, python, make, gcc")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Shared Library for BPF Compiler Collection (BCC)")
include(CPack)
