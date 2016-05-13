file(GLOB C_FILES *.c)
file(GLOB LUA_FILES *.lua)
install(FILES ${C_FILES} DESTINATION share/bcc/examples/lua)
install(PROGRAMS ${LUA_FILES} DESTINATION share/bcc/examples/lua)