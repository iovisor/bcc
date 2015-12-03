# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# to be removed
include_directories(${CMAKE_CURRENT_BINARY_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/clang)
include_directories(${LLVM_INCLUDE_DIRS})
# todo: if check for kernel version
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/compat)
add_definitions(${LLVM_DEFINITIONS})
configure_file(libbcc.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc @ONLY)

# prune unused llvm static library stuff when linking into the new .so
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--exclude-libs=ALL")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# if gcc 4.9 or higher is used, static libstdc++ is a good option
if (CMAKE_COMPILER_IS_GNUCC)
  execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
  if (GCC_VERSION VERSION_GREATER 4.9 OR GCC_VERSION VERSION_EQUAL 4.9)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -print-libgcc-file-name OUTPUT_VARIABLE GCC_LIB)
    get_filename_component(GCC_DIR "${GCC_LIB}" DIRECTORY)
    find_library(GCC_LIBSTDCPP libstdc++.a PATHS "${GCC_DIR}" NO_DEFAULT_PATH)
    if (GCC_LIBSTDCPP)
      message(STATUS "Using static-libstdc++")
      set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")
    endif()
  endif()
endif()

# tell the shared library where it is being installed so it can find shared header files
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBCC_INSTALL_PREFIX='\"${CMAKE_INSTALL_PREFIX}\"'")

add_library(bcc SHARED bpf_common.cc bpf_module.cc libbpf.c perf_reader.c)
set_target_properties(bcc PROPERTIES VERSION ${REVISION_LAST} SOVERSION 0)

# BPF is still experimental otherwise it should be available
#llvm_map_components_to_libnames(llvm_libs bpf mcjit irreader passes)
llvm_map_components_to_libnames(llvm_libs mcjit irreader passes linker
  instrumentation objcarcopts bitwriter option x86codegen)
# order is important
set(clang_libs ${libclangFrontend} ${libclangSerialization} ${libclangDriver} ${libclangParse}
  ${libclangSema} ${libclangCodeGen} ${libclangAnalysis} ${libclangRewrite} ${libclangEdit}
  ${libclangAST} ${libclangLex} ${libclangBasic})

# Link against LLVM libraries
target_link_libraries(bcc b_frontend clang_frontend ${clang_libs} ${llvm_libs} LLVMBPFCodeGen)

install(TARGETS bcc LIBRARY COMPONENT libbcc
  DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY export/ COMPONENT libbcc
  DESTINATION share/bcc/include/bcc
  FILES_MATCHING PATTERN "*.h")
install(FILES bpf_common.h ../libbpf.h COMPONENT libbcc
  DESTINATION include/bcc)
install(DIRECTORY compat/linux/ COMPONENT libbcc
  DESTINATION include/bcc/compat/linux
  FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libbcc.pc COMPONENT libbcc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

add_subdirectory(frontends)
