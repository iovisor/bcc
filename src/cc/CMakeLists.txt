
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

BISON_TARGET(Parser parser.yy ${CMAKE_CURRENT_BINARY_DIR}/parser.yy.cc COMPILE_FLAGS "-o parser.yy.cc -v --debug")
FLEX_TARGET(Lexer lexer.ll ${CMAKE_CURRENT_BINARY_DIR}/lexer.ll.cc COMPILE_FLAGS "--c++ --o lexer.ll.cc")
ADD_FLEX_BISON_DEPENDENCY(Lexer Parser)

set(CMAKE_SHARED_LINKER_FLAGS "-static-libstdc++ -Wl,--exclude-libs=ALL")

add_library(bpfprog SHARED bpf_common.cc bpf_module.cc codegen_llvm.cc
  node.cc parser.cc printer.cc type_check.cc libbpf.c b_frontend_action.cc
  kbuild_helper.cc
  ${BISON_Parser_OUTPUTS} ${FLEX_Lexer_OUTPUTS})

# BPF is still experimental otherwise it should be available
#llvm_map_components_to_libnames(llvm_libs bpf mcjit irreader passes)
llvm_map_components_to_libnames(llvm_libs mcjit irreader passes linker instrumentation objcarcopts bitwriter option)
# order is important
set(clang_libs ${libclangFrontend} ${libclangSerialization} ${libclangDriver} ${libclangParse}
  ${libclangSema} ${libclangCodeGen} ${libclangAnalysis} ${libclangRewrite} ${libclangEdit}
  ${libclangAST} ${libclangLex} ${libclangBasic})

# Link against LLVM libraries
target_link_libraries(bpfprog ${clang_libs} ${llvm_libs} LLVMBPFCodeGen mnl)
