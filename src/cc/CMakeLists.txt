# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# to be removed
include_directories(${CMAKE_CURRENT_BINARY_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/clang)
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${LIBELF_INCLUDE_DIRS})
# todo: if check for kernel version
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/compat)
add_definitions(${LLVM_DEFINITIONS})
configure_file(libbcc.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc @ONLY)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

include(static_libstdc++)

add_library(bpf-static STATIC libbpf.c perf_reader.c)
set_target_properties(bpf-static PROPERTIES OUTPUT_NAME bpf)
add_library(bpf-shared SHARED libbpf.c perf_reader.c)
set_target_properties(bpf-shared PROPERTIES OUTPUT_NAME bpf)

set(bcc_common_sources bpf_common.cc bpf_module.cc exported_files.cc)
set(bcc_table_sources table_storage.cc shared_table.cc bpffs_table.cc json_map_decl_visitor.cc)
set(bcc_util_sources ns_guard.cc common.cc)
set(bcc_sym_sources bcc_syms.cc bcc_elf.c bcc_perf_map.c bcc_proc.c)
set(bcc_api_sources BPF.cc BPFTable.cc)

add_library(bcc-shared SHARED
  ${bcc_common_sources} ${bcc_table_sources} ${bcc_sym_sources}
  ${bcc_util_sources} ${bcc_api_sources})
set_target_properties(bcc-shared PROPERTIES VERSION ${REVISION_LAST} SOVERSION 0)
set_target_properties(bcc-shared PROPERTIES OUTPUT_NAME bcc)

add_library(bcc-loader-static STATIC ${bcc_sym_sources} ${bcc_util_sources})
add_library(bcc-static STATIC
  ${bcc_common_sources} ${bcc_table_sources}
  ${bcc_util_sources} ${bcc_api_sources})
set_target_properties(bcc-static PROPERTIES OUTPUT_NAME bcc)

include(clang_libs)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${clang_lib_exclude_flags}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${llvm_lib_exclude_flags}")

set(bcc_common_libs b_frontend clang_frontend bpf-static
  ${clang_libs} ${llvm_libs} ${LIBELF_LIBRARIES})

option(ENABLE_USDT "Enable User-level Statically Defined Tracing" ON)
if(ENABLE_USDT)
  add_subdirectory(usdt)
  list(APPEND bcc_common_libs usdt-static)
endif()

# Link against LLVM libraries
target_link_libraries(bcc-shared ${bcc_common_libs})
target_link_libraries(bcc-static ${bcc_common_libs} bcc-loader-static)

install(TARGETS bcc-shared LIBRARY COMPONENT libbcc
  DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES bpf_common.h bpf_module.h bcc_syms.h bcc_exception.h file_desc.h
              libbpf.h perf_reader.h BPF.h BPFTable.h
              table_desc.h table_storage.h COMPONENT libbcc
  DESTINATION include/bcc)
install(DIRECTORY compat/linux/ COMPONENT libbcc
  DESTINATION include/bcc/compat/linux
  FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc COMPONENT libbcc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_subdirectory(frontends)
