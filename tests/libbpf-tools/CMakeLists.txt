# Licensed under the Apache License, Version 2.0 (the "License")

if(ENABLE_LIBBPF_TOOLS_TESTS)
  add_test(NAME libbpf_tools_test_smoke WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${TEST_WRAPPER} libbpf_tools_test_smoke sudo ${CMAKE_CURRENT_SOURCE_DIR}/test_tools_smoke.py)
endif()
