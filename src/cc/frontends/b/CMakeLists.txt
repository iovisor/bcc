# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

BISON_TARGET(Parser parser.yy ${CMAKE_CURRENT_BINARY_DIR}/parser.yy.cc COMPILE_FLAGS "-o parser.yy.cc -v --debug")
FLEX_TARGET(Lexer lexer.ll ${CMAKE_CURRENT_BINARY_DIR}/lexer.ll.cc COMPILE_FLAGS "--c++ --o lexer.ll.cc")
ADD_FLEX_BISON_DEPENDENCY(Lexer Parser)
if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
  set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/lexer.ll.cc PROPERTIES COMPILE_FLAGS "-Wno-deprecated-register")
endif()

add_library(b_frontend STATIC loader.cc codegen_llvm.cc node.cc parser.cc printer.cc
  type_check.cc ${BISON_Parser_OUTPUTS} ${FLEX_Lexer_OUTPUTS})
