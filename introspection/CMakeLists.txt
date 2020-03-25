# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/libbpf/include/uapi)

option(INSTALL_INTROSPECTION "Install BPF introspection tools" ON)
option(BPS_LINK_RT "Pass -lrt to linker when linking bps tool" ON)

set(bps_libs_to_link bpf-static elf z)
if(BPS_LINK_RT)
list(APPEND bps_libs_to_link rt)
endif()

add_executable(bps bps.c)
target_link_libraries(bps ${bps_libs_to_link})

install (TARGETS bps DESTINATION share/bcc/introspection)
