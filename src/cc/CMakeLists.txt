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

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -DBCC_PROG_TAG_DIR='\"${BCC_PROG_TAG_DIR}\"'")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

string(REGEX MATCH "^([0-9]+).*" _ ${LLVM_PACKAGE_VERSION})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLLVM_MAJOR_VERSION=${CMAKE_MATCH_1}")

include(static_libstdc++)

add_library(bpf-static STATIC libbpf.c perf_reader.c)
set_target_properties(bpf-static PROPERTIES OUTPUT_NAME bpf)
add_library(bpf-shared SHARED libbpf.c perf_reader.c)
set_target_properties(bpf-shared PROPERTIES VERSION ${REVISION_LAST} SOVERSION 0)
set_target_properties(bpf-shared PROPERTIES OUTPUT_NAME bpf)

set(bcc_common_sources bpf_common.cc bpf_module.cc exported_files.cc)
if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 6 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 6)
  set(bcc_common_sources ${bcc_common_sources} bcc_debug.cc)
endif()

set(bcc_table_sources table_storage.cc shared_table.cc bpffs_table.cc json_map_decl_visitor.cc)
set(bcc_util_sources ns_guard.cc common.cc)
set(bcc_sym_sources bcc_syms.cc bcc_elf.c bcc_perf_map.c bcc_proc.c)
set(bcc_common_headers libbpf.h perf_reader.h)
set(bcc_table_headers file_desc.h table_desc.h table_storage.h)
set(bcc_api_headers bpf_common.h bpf_module.h bcc_exception.h bcc_syms.h)

if(ENABLE_CLANG_JIT)
add_library(bcc-shared SHARED
  link_all.cc ${bcc_common_sources} ${bcc_table_sources} ${bcc_sym_sources}
  ${bcc_util_sources})
set_target_properties(bcc-shared PROPERTIES VERSION ${REVISION_LAST} SOVERSION 0)
set_target_properties(bcc-shared PROPERTIES OUTPUT_NAME bcc)

if(ENABLE_USDT)
  set(bcc_usdt_sources usdt/usdt.cc usdt/usdt_args.cc)
  # else undefined
endif()

add_library(bcc-loader-static STATIC ${bcc_sym_sources} ${bcc_util_sources})
target_link_libraries(bcc-loader-static elf)
add_library(bcc-static STATIC
  ${bcc_common_sources} ${bcc_table_sources} ${bcc_util_sources} ${bcc_usdt_sources})
set_target_properties(bcc-static PROPERTIES OUTPUT_NAME bcc)
set(bcc-lua-static
  ${bcc_common_sources} ${bcc_table_sources} ${bcc_sym_sources} ${bcc_util_sources})

include(clang_libs)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${clang_lib_exclude_flags}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${llvm_lib_exclude_flags}")

# bcc_common_libs_for_a for archive libraries
# bcc_common_libs_for_s for shared libraries
set(bcc_common_libs_for_a b_frontend clang_frontend bpf-static
  -Wl,--whole-archive ${clang_libs} ${llvm_libs} -Wl,--no-whole-archive
  ${LIBELF_LIBRARIES})
set(bcc_common_libs_for_s ${bcc_common_libs_for_a})
set(bcc_common_libs_for_lua b_frontend clang_frontend bpf-static
  ${clang_libs} ${llvm_libs} ${LIBELF_LIBRARIES})

if(ENABLE_CPP_API)
  add_subdirectory(api)
  list(APPEND bcc_common_libs_for_a api-static)
  # Keep all API functions
  list(APPEND bcc_common_libs_for_s -Wl,--whole-archive api-static -Wl,--no-whole-archive)
endif()

if(ENABLE_USDT)
  list(APPEND bcc_api_headers bcc_usdt.h)
  add_subdirectory(usdt)
  list(APPEND bcc_common_libs_for_a usdt-static)
  list(APPEND bcc_common_libs_for_s usdt-static)
  list(APPEND bcc_common_libs_for_lua usdt-static)
endif()

add_subdirectory(frontends)

# Link against LLVM libraries
target_link_libraries(bcc-shared ${bcc_common_libs_for_s})
target_link_libraries(bcc-static ${bcc_common_libs_for_a} bcc-loader-static)
set(bcc-lua-static ${bcc-lua-static} ${bcc_common_libs_for_lua})

install(TARGETS bcc-shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${bcc_table_headers} DESTINATION include/bcc)
install(FILES ${bcc_api_headers} DESTINATION include/bcc)
install(DIRECTORY compat/linux/ DESTINATION include/bcc/compat/linux FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif(ENABLE_CLANG_JIT)
install(FILES ${bcc_common_headers} DESTINATION include/bcc)
install(TARGETS bpf-shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
