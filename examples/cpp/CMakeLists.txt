# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_BINARY_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/libbpf/include/uapi)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

option(INSTALL_CPP_EXAMPLES "Install C++ examples. Those binaries are statically linked and can take plenty of disk space" OFF)

add_executable(HelloWorld HelloWorld.cc)
target_link_libraries(HelloWorld bcc-static)

add_executable(CPUDistribution CPUDistribution.cc)
target_link_libraries(CPUDistribution bcc-static)

add_executable(RecordMySQLQuery RecordMySQLQuery.cc)
target_link_libraries(RecordMySQLQuery bcc-static)

add_executable(TCPSendStack TCPSendStack.cc)
target_link_libraries(TCPSendStack bcc-static)

add_executable(RandomRead RandomRead.cc)
target_link_libraries(RandomRead bcc-static)

add_executable(LLCStat LLCStat.cc)
target_link_libraries(LLCStat bcc-static)

add_executable(FollyRequestContextSwitch FollyRequestContextSwitch.cc)
target_link_libraries(FollyRequestContextSwitch bcc-static)

add_executable(UseExternalMap UseExternalMap.cc)
target_link_libraries(UseExternalMap bcc-static)

add_executable(CGroupTest CGroupTest.cc)
target_link_libraries(CGroupTest bcc-static)

add_executable(TaskIterator TaskIterator.cc)
target_link_libraries(TaskIterator bcc-static)

add_executable(SkLocalStorageIterator SkLocalStorageIterator.cc)
target_link_libraries(SkLocalStorageIterator bcc-static)

add_executable(KFuncExample KFuncExample.cc)
target_link_libraries(KFuncExample bcc-static)

if(INSTALL_CPP_EXAMPLES)
  install (TARGETS HelloWorld DESTINATION share/bcc/examples/cpp)
  install (TARGETS CPUDistribution DESTINATION share/bcc/examples/cpp)
  install (TARGETS RecordMySQLQuery DESTINATION share/bcc/examples/cpp)
  install (TARGETS TCPSendStack DESTINATION share/bcc/examples/cpp)
  install (TARGETS RandomRead DESTINATION share/bcc/examples/cpp)
  install (TARGETS LLCStat DESTINATION share/bcc/examples/cpp)
  install (TARGETS FollyRequestContextSwitch DESTINATION share/bcc/examples/cpp)
  install (TARGETS UseExternalMap DESTINATION share/bcc/examples/cpp)
  install (TARGETS CGroupTest DESTINATION share/bcc/examples/cpp)
  install (TARGETS KFuncExample DESTINATION share/bcc/examples/cpp)
endif(INSTALL_CPP_EXAMPLES)

add_subdirectory(pyperf)
