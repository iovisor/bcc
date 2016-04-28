# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)

add_executable(test_static test_static.c)
target_link_libraries(test_static bcc-static)

add_test(NAME c_test_static COMMAND ${TEST_WRAPPER} c_test_static sudo ${CMAKE_CURRENT_BINARY_DIR}/test_static)

add_executable(test_libbcc
	test_libbcc.cc
	test_c_api.cc
	test_usdt_args.cc
	test_usdt_probes.cc)

target_link_libraries(test_libbcc bcc-shared dl)
add_test(NAME test_libbcc COMMAND ${TEST_WRAPPER} c_test_all sudo ${CMAKE_CURRENT_BINARY_DIR}/test_libbcc)

find_path(SDT_HEADER NAMES "sys/sdt.h")
if (SDT_HEADER)
	target_compile_definitions(test_libbcc PRIVATE HAVE_SDT_HEADER=1)
endif()
