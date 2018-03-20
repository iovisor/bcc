# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)

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

if(INSTALL_CPP_EXAMPLES)
  install (TARGETS HelloWorld DESTINATION share/bcc/examples/cpp)
  install (TARGETS CPUDistribution DESTINATION share/bcc/examples/cpp)
  install (TARGETS RecordMySQLQuery DESTINATION share/bcc/examples/cpp)
  install (TARGETS TCPSendStack DESTINATION share/bcc/examples/cpp)
  install (TARGETS RandomRead DESTINATION share/bcc/examples/cpp)
  install (TARGETS LLCStat DESTINATION share/bcc/examples/cpp)
  install (TARGETS FollyRequestContextSwitch DESTINATION share/bcc/examples/cpp)
  install (TARGETS UseExternalMap DESTINATION share/bcc/examples/cpp)
endif(INSTALL_CPP_EXAMPLES)
