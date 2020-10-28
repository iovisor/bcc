# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/libbpf/include/uapi)
include_directories(${CMAKE_SOURCE_DIR}/tests/python/include)

add_executable(test_static test_static.c)
target_link_libraries(test_static bcc-static)

add_test(NAME c_test_static COMMAND ${TEST_WRAPPER} c_test_static sudo ${CMAKE_CURRENT_BINARY_DIR}/test_static)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result -fPIC")

if(ENABLE_USDT)
set(TEST_LIBBCC_SOURCES
	test_libbcc.cc
	test_c_api.cc
	test_array_table.cc
	test_bpf_table.cc
	test_cg_storage.cc
	test_hash_table.cc
	test_map_in_map.cc
	test_perf_event.cc
	test_pinned_table.cc
	test_prog_table.cc
	test_queuestack_table.cc
	test_shared_table.cc
	test_sk_storage.cc
	test_sock_table.cc
	test_usdt_args.cc
	test_usdt_probes.cc
	utils.cc
	test_parse_tracepoint.cc)

add_executable(test_libbcc ${TEST_LIBBCC_SOURCES})

file(COPY dummy_proc_map.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_library(usdt_test_lib SHARED usdt_test_lib.cc)

add_dependencies(test_libbcc bcc-shared)
target_link_libraries(test_libbcc ${PROJECT_BINARY_DIR}/src/cc/libbcc.so dl usdt_test_lib)
set_target_properties(test_libbcc PROPERTIES INSTALL_RPATH ${PROJECT_BINARY_DIR}/src/cc)
target_compile_definitions(test_libbcc PRIVATE -DLIBBCC_NAME=\"libbcc.so\")

add_test(NAME test_libbcc COMMAND ${TEST_WRAPPER} c_test_all sudo ${CMAKE_CURRENT_BINARY_DIR}/test_libbcc)

if(LIBBPF_FOUND)
  add_executable(test_libbcc_no_libbpf ${TEST_LIBBCC_SOURCES})
  add_dependencies(test_libbcc_no_libbpf bcc-shared-no-libbpf)

  target_link_libraries(test_libbcc_no_libbpf ${PROJECT_BINARY_DIR}/src/cc/libbcc-no-libbpf.so dl usdt_test_lib ${LIBBPF_LIBRARIES})
  set_target_properties(test_libbcc_no_libbpf PROPERTIES INSTALL_RPATH ${PROJECT_BINARY_DIR}/src/cc)
  target_compile_definitions(test_libbcc_no_libbpf PRIVATE -DLIBBCC_NAME=\"libbcc-no-libbpf.so\")

  add_test(NAME test_libbcc_no_libbpf COMMAND ${TEST_WRAPPER} c_test_all_no_libbpf sudo ${CMAKE_CURRENT_BINARY_DIR}/test_libbcc_no_libbpf)
endif()

endif(ENABLE_USDT)
