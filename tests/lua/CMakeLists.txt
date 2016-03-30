find_program(LUAJIT luajit)

if(LUAJIT)
	add_test(NAME lua_test_clang WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			COMMAND sudo ${LUAJIT} test_clang.lua)
endif()
