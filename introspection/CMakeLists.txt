# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${PROJECT_SOURCE_DIR}/src/cc)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/api)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/libbpf/include/uapi)

option(INSTALL_INTROSPECTION "Install BPF introspection tools" ON)
option(BPS_LINK_RT "Pass -lrt to linker when linking bps tool" ON)

# Note that the order matters! bpf-static first, the rest later
if(CMAKE_USE_LIBBPF_PACKAGE AND LIBBPF_FOUND)
set(bps_libs_to_link bpf-shared ${LIBBPF_LIBRARIES})
else()
set(bps_libs_to_link bpf-static)
endif()
list(APPEND bps_libs_to_link elf z)
if(BPS_LINK_RT)
list(APPEND bps_libs_to_link rt)
endif()

add_executable(bps bps.c)
target_link_libraries(bps ${bps_libs_to_link})

install (TARGETS bps DESTINATION share/bcc/introspection)
