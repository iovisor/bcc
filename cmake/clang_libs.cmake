if(ENABLE_LLVM_SHARED)
set(llvm_libs "LLVM")
else()
set(llvm_raw_libs bitwriter bpfcodegen debuginfodwarf irreader linker
  mcjit objcarcopts option passes nativecodegen lto)
list(FIND LLVM_AVAILABLE_LIBS "LLVMCoverage" _llvm_coverage)
if (${_llvm_coverage} GREATER -1)
  list(APPEND llvm_raw_libs coverage)
endif()
list(FIND LLVM_AVAILABLE_LIBS "LLVMCoroutines" _llvm_coroutines)
if (${_llvm_coroutines} GREATER -1)
  list(APPEND llvm_raw_libs coroutines)
endif()
if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 6 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 6)
  list(APPEND llvm_raw_libs bpfasmparser)
  list(APPEND llvm_raw_libs bpfdisassembler)
endif()
llvm_map_components_to_libnames(_llvm_libs ${llvm_raw_libs})
llvm_expand_dependencies(llvm_libs ${_llvm_libs})
endif()

# order is important
set(clang_libs
  ${libclangFrontend}
  ${libclangSerialization}
  ${libclangDriver})

if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 8 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 8)
  list(APPEND clang_libs ${libclangASTMatchers})
endif()

list(APPEND clang_libs
  ${libclangParse}
  ${libclangSema}
  ${libclangCodeGen}
  ${libclangAnalysis}
  ${libclangRewrite}
  ${libclangEdit}
  ${libclangAST}
  ${libclangLex}
  ${libclangBasic})

# prune unused llvm static library stuff when linking into the new .so
set(_exclude_flags)
foreach(_lib ${clang_libs})
  get_filename_component(_lib ${_lib} NAME)
  set(_exclude_flags "${_exclude_flags} -Wl,--exclude-libs=${_lib}")
endforeach(_lib)
set(clang_lib_exclude_flags "${_exclude_flags}")

set(_exclude_flags)
foreach(_lib ${llvm_libs})
  get_filename_component(_lib ${_lib} NAME)
  set(_exclude_flags "${_exclude_flags} -Wl,--exclude-libs=lib${_lib}.a")
endforeach(_lib)
set(llvm_lib_exclude_flags "${_exclude_flags}")
