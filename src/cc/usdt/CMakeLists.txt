add_library(usdt-static STATIC usdt_args.cc usdt.cc)
install(TARGETS usdt-static LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
