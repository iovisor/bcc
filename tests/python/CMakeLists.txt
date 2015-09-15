# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

add_test(NAME py_test_dump_func WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_dump_func simple ${CMAKE_CURRENT_SOURCE_DIR}/test_dump_func.py)
