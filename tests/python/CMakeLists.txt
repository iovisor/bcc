# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

find_program(ARPING arping)
if(ARPING STREQUAL "ARPING-NOTFOUND")
  message(WARNING "Recommended test program 'arping' not found")
endif()
find_program(NETPERF netperf)
if(NETPERF STREQUAL "NETPERF-NOTFOUND")
  message(WARNING "Recommended test program 'netperf' not found")
endif()
find_program(IPERF iperf)
if(IPERF STREQUAL "IPERF-NOTFOUND")
  message(WARNING "Recommended test program 'iperf' not found")
endif()

add_test(NAME py_test_stat1_b WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_stat1_b namespace ${CMAKE_CURRENT_SOURCE_DIR}/test_stat1.py test_stat1.b proto.b)
add_test(NAME py_test_bpf_log WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_bpf_prog sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_bpf_log.py)
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
add_test(NAME py_test_trace4 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_trace4 sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_trace4.py)
add_test(NAME py_test_probe_count WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_probe_count sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_probe_count.py)
add_test(NAME py_test_debuginfo WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_debuginfo sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_debuginfo.py)
add_test(NAME py_test_brb WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_brb_c sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_brb.py test_brb.c)
add_test(NAME py_test_brb2 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_brb2_c sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_brb2.py test_brb2.c)
add_test(NAME py_test_clang WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_clang sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_clang.py)
add_test(NAME py_test_histogram WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_histogram sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_histogram.py)
add_test(NAME py_test_callchain WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_callchain sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_callchain.py)
add_test(NAME py_array WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_array sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_array.py)
add_test(NAME py_uprobes WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_uprobes sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_uprobes.py)
add_test(NAME py_test_stackid WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_stackid sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_stackid.py)
add_test(NAME py_test_tracepoint WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_tracepoint sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_tracepoint.py)
add_test(NAME py_test_perf_event WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_perf_event sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_perf_event.py)
add_test(NAME py_test_utils WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_utils sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_utils.py)
add_test(NAME py_test_percpu WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_percpu sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_percpu.py)
add_test(NAME py_test_dump_func WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_dump_func simple ${CMAKE_CURRENT_SOURCE_DIR}/test_dump_func.py)
add_test(NAME py_test_tools_smoke WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_tools_smoke sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_tools_smoke.py)
add_test(NAME py_test_tools_memleak WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_tools_memleak sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_tools_memleak.py)
add_test(NAME py_test_usdt WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_usdt sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_usdt.py)
add_test(NAME py_test_usdt2 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ${TEST_WRAPPER} py_test_usdt2 sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_usdt2.py)
