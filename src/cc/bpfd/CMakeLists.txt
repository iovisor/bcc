# Copyright (c) Jazel Canseco, 2018
# Copyright (c) Adrian Ratiu, 2019
# Licensed under the Apache License, Version 2.0 (the "License")

cmake_minimum_required(VERSION 2.8.7)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake)

find_package(LibElf REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..
                    ${CMAKE_CURRENT_SOURCE_DIR}/../libbpf/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../libbpf/include/uapi)

add_library(bcc-bpfd-static STATIC ../common.cc ../bcc_syms.cc ../ns_guard.cc ../bcc_proc.c
                                   ../libbpf.c ../perf_reader.c ../bcc_elf.c ../bcc_perf_map.c)

file(GLOB libbpf_sources "../libbpf/src/*.c")
add_library(bpf-bpfd-static STATIC ../libbpf.c ${libbpf_sources})

add_executable(bpfd bpfd.c base64.c remote_perf_reader.c utils.c cmd_parsers.c)
target_link_libraries(bpfd bpf-bpfd-static bcc-bpfd-static)
target_link_libraries(bpfd ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})

install(TARGETS bpfd RUNTIME DESTINATION bin)
