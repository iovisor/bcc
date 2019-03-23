# Copyright (c) Jazel Canseco, 2018
# Licensed under the Apache License, Version 2.0 (the "License")

add_library(bcc-bpfd-static STATIC ../common.cc ../bcc_syms.cc ../ns_guard.cc ../bcc_proc.c
                                   ../libbpf.c ../perf_reader.c ../bcc_elf.c ../bcc_perf_map.c)

add_executable(bpfd bpfd.c base64.c remote_perf_reader.c utils.c cmd_parsers.c)
target_link_libraries(bpfd bpf-static)
target_link_libraries(bpfd bcc-bpfd-static)
target_link_libraries(bpfd ${LIBELF_LIBRARIES})

install(TARGETS bpfd RUNTIME DESTINATION bin)
