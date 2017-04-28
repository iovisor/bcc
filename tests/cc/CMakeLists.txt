# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)

add_executable(test_static test_static.c)
target_link_libraries(test_static bcc-static)

add_test(NAME c_test_static COMMAND ${TEST_WRAPPER} c_test_static sudo ${CMAKE_CURRENT_BINARY_DIR}/test_static)

add_executable(test_libbcc
	test_libbcc.cc
	test_c_api.cc
	test_array_table.cc
	test_bpf_table.cc
	test_hash_table.cc
	test_usdt_args.cc
	test_usdt_probes.cc)

target_link_libraries(test_libbcc bcc-shared dl)
add_test(NAME test_libbcc COMMAND ${TEST_WRAPPER} c_test_all sudo ${CMAKE_CURRENT_BINARY_DIR}/test_libbcc)

find_path(SDT_HEADER NAMES "sys/sdt.h")
if (SDT_HEADER)
	target_compile_definitions(test_libbcc PRIVATE HAVE_SDT_HEADER=1)
endif()

if (CMAKE_COMPILER_IS_GNUCC)
	execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
	if (GCC_VERSION VERSION_GREATER 5.1 OR GCC_VERSION VERSION_EQUAL 5.1)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_USE_CXX11_ABI=0")
		message(STATUS "Using old C++ ABI for libbcc test")
	endif()
endif()
