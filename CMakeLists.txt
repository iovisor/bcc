# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
cmake_minimum_required(VERSION 2.8.7)

project(bcc)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

enable_testing()

include(cmake/GetGitRevisionDescription.cmake)
include(cmake/version.cmake)
include(CMakeDependentOption)
include(GNUInstallDirs)
include(CheckCXXCompilerFlag)
include(cmake/FindCompilerFlag.cmake)

option(ENABLE_LLVM_SHARED "Enable linking LLVM as a shared library" OFF)
option(ENABLE_CLANG_JIT "Enable Loading BPF through Clang Frontend" ON)
option(ENABLE_USDT "Enable User-level Statically Defined Tracing" ON)
CMAKE_DEPENDENT_OPTION(ENABLE_CPP_API "Enable C++ API" ON "ENABLE_USDT" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if(NOT PYTHON_ONLY AND ENABLE_CLANG_JIT)
find_package(BISON)
find_package(FLEX)
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM: ${LLVM_INCLUDE_DIRS} ${LLVM_PACKAGE_VERSION}")
find_package(LibElf REQUIRED)

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
find_library(libclangASTMatchers NAMES clangASTMatchers HINTS ${CLANG_SEARCH})
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

if(NOT DEFINED BCC_PROG_TAG_DIR)
  set(BCC_PROG_TAG_DIR "/var/tmp/bcc")
endif()

# As reported in issue #735, GCC 6 has some behavioral problems when
# dealing with -isystem. Hence, skip the warning optimization
# altogether on that compiler.
option(USINGISYSTEM "using -isystem" ON)
execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
if (USINGISYSTEM AND GCC_VERSION VERSION_LESS 6.0)
  # iterate over all available directories in LLVM_INCLUDE_DIRS to
  # generate a correctly tokenized list of parameters
  foreach(ONE_LLVM_INCLUDE_DIR ${LLVM_INCLUDE_DIRS})
    set(CXX_ISYSTEM_DIRS "${CXX_ISYSTEM_DIRS} -isystem ${ONE_LLVM_INCLUDE_DIR}")
  endforeach()
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

endif(NOT PYTHON_ONLY AND ENABLE_CLANG_JIT)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall ${CXX_ISYSTEM_DIRS}")

add_subdirectory(src)
add_subdirectory(introspection)
if(ENABLE_CLANG_JIT)
add_subdirectory(examples)
add_subdirectory(man)
add_subdirectory(tests)
add_subdirectory(tools)
endif(ENABLE_CLANG_JIT)
