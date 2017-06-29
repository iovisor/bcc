set(bcc_api_sources BPF.cc BPFTable.cc)
add_library(api-static STATIC ${bcc_api_sources})
install(FILES BPF.h BPFTable.h COMPONENT libbcc DESTINATION include/bcc)
