find_program(GZIP gzip)
file(GLOB FILES *.8)
set(GZFILES "")
foreach(FIL ${FILES})
  get_filename_component(NAME ${FIL} NAME)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.gz
    COMMAND ${GZIP} -c ${FIL} > ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.gz
    DEPENDS ${FIL})
  list(APPEND GZFILES "${CMAKE_CURRENT_BINARY_DIR}/${NAME}.gz")
endforeach()
add_custom_target(man ALL DEPENDS ${GZFILES})
install(FILES ${GZFILES} DESTINATION share/bcc/man/man8)
