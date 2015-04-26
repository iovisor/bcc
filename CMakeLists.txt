cmake_minimum_required(VERSION 2.8.7)

project(bpf-tools)

find_package(BISON)
find_package(FLEX)
find_package(LLVM REQUIRED CONFIG)
find_program(XXD xxd)
if (${XXD} STREQUAL "XXD-NOTFOUND")
  message(FATAL_ERROR "program xxd not found, install vim-common")
endif()
find_program(CLANG clang)
if (${CLANG} STREQUAL "CLANG-NOTFOUND")
  message(FATAL_ERROR "program clang not found, install clang with bpf support")
endif()

set(CMAKE_C_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")

add_subdirectory(jit)
