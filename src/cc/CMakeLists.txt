
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

BISON_TARGET(Parser parser.yy ${CMAKE_CURRENT_BINARY_DIR}/parser.yy.cc COMPILE_FLAGS "-o parser.yy.cc -v --debug")
FLEX_TARGET(Lexer lexer.ll ${CMAKE_CURRENT_BINARY_DIR}/lexer.ll.cc COMPILE_FLAGS "--c++ --o lexer.ll.cc")
ADD_FLEX_BISON_DEPENDENCY(Lexer Parser)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bitops.bc
  COMMAND ${CLANG}
  ARGS -O3 -emit-llvm -o bitops.bc -I${CMAKE_SOURCE_DIR}/jit/compat/include
    -c ${CMAKE_CURRENT_SOURCE_DIR}/bitops.c
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bitops.c ${CMAKE_CURRENT_SOURCE_DIR}/bpf_helpers.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Generating bitops IR")
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bitops.h
  COMMAND ${XXD} ARGS -i bitops.bc bitops.h
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/bitops.bc
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Generating bitops.h")
add_custom_target(bitops DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/bitops.h)

set(CMAKE_SHARED_LINKER_FLAGS "-static-libstdc++ -Wl,--exclude-libs=ALL")

add_library(bpfprog SHARED bpf_common.cc bpf_program.cc codegen_llvm.cc
  node.cc parser.cc printer.cc type_check.cc libbpf.c
  ${BISON_Parser_OUTPUTS} ${FLEX_Lexer_OUTPUTS} ${CMAKE_CURRENT_BINARY_DIR}/bitops.h)

# BPF is still experimental otherwise it should be available
#llvm_map_components_to_libnames(llvm_libs bpf mcjit irreader passes)
llvm_map_components_to_libnames(llvm_libs mcjit irreader passes)

# Link against LLVM libraries
target_link_libraries(bpfprog ${llvm_libs} LLVMBPFCodeGen mnl)
