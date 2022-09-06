install(FILES BPF.h BPFTable.h COMPONENT libbcc DESTINATION include/bcc)
set(bcc_api_sources
  "${CMAKE_CURRENT_SOURCE_DIR}/BPF.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/BPFTable.cc"
  PARENT_SCOPE)
