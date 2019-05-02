find_package(LuaJIT)
find_program(LUAJIT luajit)

if (LUAJIT_LIBRARIES AND LUAJIT)
	FILE(GLOB_RECURSE SRC_LUA
		${CMAKE_CURRENT_SOURCE_DIR}/bcc/*.lua
		${CMAKE_CURRENT_SOURCE_DIR}/bcc/vendor/*.lua
		${CMAKE_CURRENT_SOURCE_DIR}/bpf/*.lua)

	ADD_CUSTOM_COMMAND(
		OUTPUT bcc.lua
		COMMAND ${LUAJIT} ${CMAKE_CURRENT_SOURCE_DIR}/src/squish.lua ${CMAKE_CURRENT_SOURCE_DIR}
		DEPENDS ${SRC_LUA} ${CMAKE_CURRENT_SOURCE_DIR}/squishy
	)

	# LuaJIT doesn't use usual arch naming, so we have to convert
	# between CMake and Luajit while cross-compiling.
	if (CMAKE_CROSSCOMPILING)
		SET (LUAJIT_TARGET_ARCH "-a")
		# https://github.com/LuaJIT/LuaJIT/blob/f0e865dd4861520258299d0f2a56491bd9d602e1/src/jit/bcsave.lua#L30
		# https://github.com/LuaJIT/LuaJIT/blob/f0e865dd4861520258299d0f2a56491bd9d602e1/src/jit/bcsave.lua#L65
		if (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "arm64")
		elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64_be")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "arm64be")
		elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "arm")
		elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "^(i.86)$")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "x86")
		elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "mips")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "mips")
		elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "mipsel")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "mipsel")
		elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "powerpc")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "ppc")
		elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
			SET (LUAJIT_TARGET_ARCH ${LUAJIT_TARGET_ARCH} "x64")
		else()
			MESSAGE(FATAL_ERROR "${CMAKE_SYSTEM_PROCESSOR} is not supported by LuaJIT")
		endif()
	endif()

	ADD_CUSTOM_COMMAND(
		OUTPUT bcc.o
		COMMAND ${LUAJIT} -bg bcc.lua ${LUAJIT_TARGET_ARCH} bcc.o
		DEPENDS bcc.lua
	)

	include_directories(${LUAJIT_INCLUDE_DIR})
	add_executable(bcc-lua src/main.c bcc.o)
	set_target_properties(bcc-lua PROPERTIES LINKER_LANGUAGE C)
	target_link_libraries(bcc-lua ${LUAJIT_LIBRARIES})
	target_link_libraries(bcc-lua ${bcc-lua-static})
	if (NOT COMPILER_NOPIE_FLAG EQUAL "")
		target_link_libraries(bcc-lua ${COMPILER_NOPIE_FLAG})
	endif()

	install(TARGETS bcc-lua RUNTIME DESTINATION bin)
endif()
