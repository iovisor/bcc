find_program(LUAJIT luajit)

if(LUAJIT)
	add_test(NAME lua_test_clang WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMAND ${TEST_WRAPPER} lua_test_clang sudo ${LUAJIT} test_clang.lua)

	add_test(NAME lua_test_uprobes WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMAND ${TEST_WRAPPER} lua_test_uprobes sudo ${LUAJIT} test_uprobes.lua)

	add_test(NAME lua_test_dump WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMAND ${TEST_WRAPPER} lua_test_dump sudo ${LUAJIT} test_dump.lua)

	add_test(NAME lua_test_standalone WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_standalone.sh)
endif()
