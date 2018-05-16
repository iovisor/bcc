# Copyright (c) Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_SOURCE_DIR}/src/cc)
include_directories(${CMAKE_SOURCE_DIR}/src/cc/api)

option(INSTALL_INTROSPECTION "Install BPF introspection tools" ON)

add_executable(bps bps.c)
target_link_libraries(bps bpf-static)

install (TARGETS bps DESTINATION share/bcc/introspection)
