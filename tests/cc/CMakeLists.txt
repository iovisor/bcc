# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)

add_executable(test_static test_static.c)
target_link_libraries(test_static bcc-static)

add_test(NAME c_test_static COMMAND ${TEST_WRAPPER} c_test_static sudo ${CMAKE_CURRENT_BINARY_DIR}/test_static)

add_executable(test_c_api test_c_api.c)
target_link_libraries(test_c_api bcc-shared dl)

add_test(NAME test_c_api COMMAND ${TEST_WRAPPER} c_test_api sudo ${CMAKE_CURRENT_BINARY_DIR}/test_c_api)
