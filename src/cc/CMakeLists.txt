# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LLVM_INCLUDE_DIRS})
# todo: if check for kernel version
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/compat)
add_definitions(${LLVM_DEFINITIONS})

BISON_TARGET(Parser parser.yy ${CMAKE_CURRENT_BINARY_DIR}/parser.yy.cc COMPILE_FLAGS "-o parser.yy.cc -v --debug")
FLEX_TARGET(Lexer lexer.ll ${CMAKE_CURRENT_BINARY_DIR}/lexer.ll.cc COMPILE_FLAGS "--c++ --o lexer.ll.cc")
ADD_FLEX_BISON_DEPENDENCY(Lexer Parser)

# prune unused llvm static library stuff when linking into the new .so
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--exclude-libs=ALL")

# if gcc 4.9 or higher is used, static libstdc++ is a good option
if (CMAKE_COMPILER_IS_GNUCC)
  execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
  if (GCC_VERSION VERSION_GREATER 4.9 OR GCC_VERSION VERSION_EQUAL 4.9)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")
  endif()
endif()

# tell the shared library where it is being installed so it can find shared header files
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBCC_INSTALL_PREFIX='\"${CMAKE_INSTALL_PREFIX}\"'")

add_library(bpfprog SHARED bpf_common.cc bpf_module.cc codegen_llvm.cc
  node.cc parser.cc printer.cc type_check.cc libbpf.c b_frontend_action.cc
  kbuild_helper.cc
  ${BISON_Parser_OUTPUTS} ${FLEX_Lexer_OUTPUTS})

# BPF is still experimental otherwise it should be available
#llvm_map_components_to_libnames(llvm_libs bpf mcjit irreader passes)
#llvm_map_components_to_libnames(llvm_libs mcjit irreader passes linker instrumentation objcarcopts bitwriter option)
set(llvm_libs "LLVMMCJIT;LLVMIRReader;LLVMPasses;LLVMLinker;LLVMInstrumentation;LLVMObjCARCOpts;LLVMBitWriter;LLVMOption")

# order is important
set(clang_libs ${libclangFrontend} ${libclangSerialization} ${libclangDriver} ${libclangParse}
  ${libclangSema} ${libclangCodeGen} ${libclangAnalysis} ${libclangRewrite} ${libclangEdit}
  ${libclangAST} ${libclangLex} ${libclangBasic})

# Link against LLVM libraries
target_link_libraries(bpfprog ${clang_libs} ${llvm_libs} LLVMBPFCodeGen)

install(TARGETS bpfprog LIBRARY DESTINATION lib${LIBSUFFIX})
install(DIRECTORY export/ DESTINATION share/bcc/include/bcc
  FILES_MATCHING PATTERN "*.h")
