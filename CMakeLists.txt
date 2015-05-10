cmake_minimum_required(VERSION 2.8.7)

project(bpf-tools)
set(CMAKE_BUILD_TYPE Debug)

enable_testing()

find_package(BISON)
find_package(FLEX)
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM: ${LLVM_INCLUDE_DIRS}")

# clang is linked as a library, but the library path searching is
# primitively supported, unlike libLLVM
set(CLANG_SEARCH "/opt/local/llvm/lib")
find_library(libclangAnalysis NAMES clangAnalysis HINTS ${CLANG_SEARCH})
find_library(libclangAST NAMES clangAST HINTS ${CLANG_SEARCH})
find_library(libclangBasic NAMES clangBasic HINTS ${CLANG_SEARCH})
find_library(libclangCodeGen NAMES clangCodeGen HINTS ${CLANG_SEARCH})
find_library(libclangDriver NAMES clangDriver HINTS ${CLANG_SEARCH})
find_library(libclangEdit NAMES clangEdit HINTS ${CLANG_SEARCH})
find_library(libclangFrontend NAMES clangFrontend HINTS ${CLANG_SEARCH})
find_library(libclangLex NAMES clangLex HINTS ${CLANG_SEARCH})
find_library(libclangParse NAMES clangParse HINTS ${CLANG_SEARCH})
find_library(libclangSema NAMES clangSema HINTS ${CLANG_SEARCH})
find_library(libclangSerialization NAMES clangSerialization HINTS ${CLANG_SEARCH})

set(CMAKE_C_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")

add_subdirectory(src)
add_subdirectory(tests)
