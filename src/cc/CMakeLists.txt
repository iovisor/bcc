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
configure_file(libbpfprog.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libbpfprog.pc @ONLY)

# prune unused llvm static library stuff when linking into the new .so
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--exclude-libs=ALL")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# if gcc 4.9 or higher is used, static libstdc++ is a good option
if (CMAKE_COMPILER_IS_GNUCC)
  execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
  if (GCC_VERSION VERSION_GREATER 4.9 OR GCC_VERSION VERSION_EQUAL 4.9)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")
  endif()
endif()

# tell the shared library where it is being installed so it can find shared header files
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBCC_INSTALL_PREFIX='\"${CMAKE_INSTALL_PREFIX}\"'")

add_library(bpfprog SHARED bpf_common.cc bpf_module.cc libbpf.c)

# BPF is still experimental otherwise it should be available
#llvm_map_components_to_libnames(llvm_libs bpf mcjit irreader passes)
llvm_map_components_to_libnames(llvm_libs mcjit irreader passes linker instrumentation objcarcopts bitwriter option)
# order is important
set(clang_libs ${libclangFrontend} ${libclangSerialization} ${libclangDriver} ${libclangParse}
  ${libclangSema} ${libclangCodeGen} ${libclangAnalysis} ${libclangRewrite} ${libclangEdit}
  ${libclangAST} ${libclangLex} ${libclangBasic})

# Link against LLVM libraries
target_link_libraries(bpfprog b_frontend clang_frontend ${clang_libs} ${llvm_libs} LLVMBPFCodeGen)

install(TARGETS bpfprog LIBRARY DESTINATION lib${LIBSUFFIX})
install(DIRECTORY export/ DESTINATION share/bcc/include/bcc
  FILES_MATCHING PATTERN "*.h")
install(FILES bpf_common.h ../libbpf.h DESTINATION include/bcc)
install(DIRECTORY compat/linux/ DESTINATION include/bcc/compat/linux
  FILES_MATCHING PATTERN "*.h")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libbpfprog.pc DESTINATION lib${LIBSUFFIX}/pkgconfig)

add_subdirectory(frontends)
