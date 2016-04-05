include(cmake/FindLuaJIT.cmake)

if (LUAJIT_LIBRARIES)
	find_program(LUAJIT luajit)
	FILE(GLOB_RECURSE SRC_LUA ${CMAKE_CURRENT_SOURCE_DIR}/bcc/*/*.lua)

	ADD_CUSTOM_COMMAND(
		OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/bcc.lua
		COMMAND ${LUAJIT} src/squish.lua
		DEPENDS ${SRC_LUA} ${CMAKE_CURRENT_SOURCE_DIR}/squishy
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)

	ADD_CUSTOM_COMMAND(
		OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/bcc.o
		COMMAND ${LUAJIT} -bg src/bcc.lua src/bcc.o
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/bcc.lua
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)

	include_directories(${LUAJIT_INCLUDE_DIR})
	add_executable(bcc-lua src/main.c src/bcc.o)
	target_link_libraries(bcc-lua ${LUAJIT_LIBRARIES})

	install(TARGETS bcc-lua RUNTIME DESTINATION bin)
endif()
