# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
configure_file(wrapper.sh.in "${CMAKE_CURRENT_BINARY_DIR}/wrapper.sh" @ONLY)

set(TEST_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/wrapper.sh)

add_test(NAME style-check COMMAND ${CMAKE_SOURCE_DIR}/scripts/style-check.sh)

add_subdirectory(cc)
add_subdirectory(python)
add_subdirectory(lua)
