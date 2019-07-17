# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/libbpf/include/uapi)
include_directories(${CMAKE_SOURCE_DIR}/tests/python/include)

add_executable(test_static test_static.c)
target_link_libraries(test_static bcc-static)

add_test(NAME c_test_static COMMAND ${TEST_WRAPPER} c_test_static sudo ${CMAKE_CURRENT_BINARY_DIR}/test_static)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result")

if(ENABLE_USDT)
add_executable(test_libbcc
	test_libbcc.cc
	test_c_api.cc
	test_array_table.cc
	test_bpf_table.cc
	test_hash_table.cc
	test_perf_event.cc
	test_pinned_table.cc
	test_prog_table.cc
	test_shared_table.cc
	test_usdt_args.cc
	test_usdt_probes.cc
	utils.cc)
file(COPY dummy_proc_map.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_library(usdt_test_lib SHARED usdt_test_lib.c)

target_link_libraries(test_libbcc bcc-shared dl usdt_test_lib)
add_test(NAME test_libbcc COMMAND ${TEST_WRAPPER} c_test_all sudo ${CMAKE_CURRENT_BINARY_DIR}/test_libbcc)

endif(ENABLE_USDT)
