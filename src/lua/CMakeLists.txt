find_package(LuaJIT)
find_program(LUAJIT luajit)

if (LUAJIT_LIBRARIES AND LUAJIT)
	FILE(GLOB_RECURSE SRC_LUA ${CMAKE_CURRENT_SOURCE_DIR}/bcc/*/*.lua)

	ADD_CUSTOM_COMMAND(
		OUTPUT bcc.lua
		COMMAND ${LUAJIT} ${CMAKE_CURRENT_SOURCE_DIR}/src/squish.lua ${CMAKE_CURRENT_SOURCE_DIR}
		DEPENDS ${SRC_LUA} ${CMAKE_CURRENT_SOURCE_DIR}/squishy
	)

	ADD_CUSTOM_COMMAND(
		OUTPUT bcc.o
		COMMAND ${LUAJIT} -bg bcc.lua bcc.o
		DEPENDS bcc.lua
	)

	include_directories(${LUAJIT_INCLUDE_DIR})
	add_executable(bcc-lua src/main.c bcc.o)
	target_link_libraries(bcc-lua ${LUAJIT_LIBRARIES})

	install(TARGETS bcc-lua RUNTIME DESTINATION bin)
endif()
