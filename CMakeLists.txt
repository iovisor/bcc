# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
cmake_minimum_required(VERSION 2.8.7)

project(bcc)
set(CMAKE_BUILD_TYPE Release)

enable_testing()

include(cmake/GetGitRevisionDescription.cmake)
include(cmake/version.cmake)
include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if(NOT PYTHON_ONLY)
find_package(BISON)
find_package(FLEX)
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM: ${LLVM_INCLUDE_DIRS}")

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

# Set to a string path if system places kernel lib directory in
# non-default location.
if(NOT DEFINED BCC_KERNEL_MODULES_DIR)
  set(BCC_KERNEL_MODULES_DIR "/lib/modules")
endif()

find_package(LibElf REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

# As reported in issue #735, GCC 6 has some behavioral problems when
# dealing with -isystem. Hence, skip the warning optimization
# altogether on that compiler.
execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
if (GCC_VERSION VERSION_LESS 6.0)
  # iterate over all available directories in LLVM_INCLUDE_DIRS to
  # generate a correctly tokenized list of parameters
  foreach(ONE_LLVM_INCLUDE_DIR ${LLVM_INCLUDE_DIRS})
    set(CXX_ISYSTEM_DIRS "${CXX_ISYSTEM_DIRS} -isystem ${ONE_LLVM_INCLUDE_DIR}")
  endforeach()
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall ${CXX_ISYSTEM_DIRS}")
endif()

add_subdirectory(examples)
add_subdirectory(man)
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(tools)
