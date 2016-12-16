# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)

add_executable(HelloWorld HelloWorld.cc)
target_link_libraries(HelloWorld bcc-static)
install (TARGETS HelloWorld DESTINATION share/bcc/examples/cpp)

add_executable(CPUDistribution CPUDistribution.cc)
target_link_libraries(CPUDistribution bcc-static)
install (TARGETS CPUDistribution DESTINATION share/bcc/examples/cpp)

add_executable(RecordMySQLQuery RecordMySQLQuery.cc)
target_link_libraries(RecordMySQLQuery bcc-static)
install (TARGETS RecordMySQLQuery DESTINATION share/bcc/examples/cpp)

add_executable(TCPSendStack TCPSendStack.cc)
target_link_libraries(TCPSendStack bcc-static)
install (TARGETS TCPSendStack DESTINATION share/bcc/examples/cpp)

add_executable(RandomRead RandomRead.cc)
target_link_libraries(RandomRead bcc-static)
install (TARGETS RandomRead DESTINATION share/bcc/examples/cpp)

add_executable(LLCStat LLCStat.cc)
target_link_libraries(LLCStat bcc-static)
install (TARGETS LLCStat DESTINATION share/bcc/examples/cpp)

add_executable(FollyRequestContextSwitch FollyRequestContextSwitch.cc)
target_link_libraries(FollyRequestContextSwitch bcc-static)
install (TARGETS FollyRequestContextSwitch DESTINATION share/bcc/examples/cpp)
