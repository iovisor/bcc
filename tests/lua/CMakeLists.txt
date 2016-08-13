find_program(LUAJIT luajit)
find_program(BUSTED busted)

if(LUAJIT)
	add_test(NAME lua_test_clang WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMAND ${TEST_WRAPPER} lua_test_clang sudo ${LUAJIT} test_clang.lua)

	add_test(NAME lua_test_uprobes WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMAND ${TEST_WRAPPER} lua_test_uprobes sudo ${LUAJIT} test_uprobes.lua)

	add_test(NAME lua_test_dump WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		COMMAND ${TEST_WRAPPER} lua_test_dump sudo ${LUAJIT} test_dump.lua)

	add_test(NAME lua_test_standalone WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_standalone.sh)

	if(BUSTED)
		add_test(NAME lua_test_busted WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			COMMAND busted --lua=${LUAJIT} -m "${CMAKE_CURRENT_SOURCE_DIR}/../../src/lua/?.lua" -m "${CMAKE_CURRENT_SOURCE_DIR}/../../src/lua/?/init.lua;")
	endif()
endif()
