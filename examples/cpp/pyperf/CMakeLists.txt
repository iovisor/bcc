# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/libbpf/include/uapi)

add_executable(PyPerf PyPerf.cc PyPerfUtil.cc PyPerfBPFProgram.cc PyPerfLoggingHelper.cc PyPerfDefaultPrinter.cc Py36Offsets.cc)
target_link_libraries(PyPerf bcc-static)

if(INSTALL_CPP_EXAMPLES)
  install (TARGETS PyPerf DESTINATION share/bcc/examples/cpp)
endif(INSTALL_CPP_EXAMPLES)
