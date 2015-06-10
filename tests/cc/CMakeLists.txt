# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
add_test(NAME py_test_stat1_b WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_stat1_b namespace ${CMAKE_CURRENT_SOURCE_DIR}/test_stat1.py test_stat1.b proto.b)
add_test(NAME py_test_stat1_c WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_stat1_c namespace ${CMAKE_CURRENT_SOURCE_DIR}/test_stat1.py test_stat1.c)
#add_test(NAME py_test_xlate1_b WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#  COMMAND ${TEST_WRAPPER} py_xlate1_b namespace ${CMAKE_CURRENT_SOURCE_DIR}/test_xlate1.py test_xlate1.b proto.b)
add_test(NAME py_test_xlate1_c WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_xlate1_c namespace ${CMAKE_CURRENT_SOURCE_DIR}/test_xlate1.py test_xlate1.c)
add_test(NAME py_test_call1 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_call1_c namespace ${CMAKE_CURRENT_SOURCE_DIR}/test_call1.py test_call1.c)
add_test(NAME py_test_trace1 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_trace1 sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_trace1.py test_trace1.b kprobe.b)
add_test(NAME py_test_trace2 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_trace2 sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_trace2.py)
add_test(NAME py_test_trace3_c WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_trace3_c sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_trace3.py test_trace3.c)
add_test(NAME py_test_brb WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_brb_c sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_brb.py test_brb.c)
