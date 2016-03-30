find_program(LUAJIT luajit)
find_program(SUDO sudo)

if(LUAJIT)
	add_test(NAME lua_test_clang WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMAND ${SUDO} ${LUAJIT} test_clang.lua)
endif()
