set(EXAMPLE_PROGRAMS hello_world.py)
install(PROGRAMS ${EXAMPLE_PROGRAMS} DESTINATION share/bcc/examples)

if(ENABLE_CLANG_JIT)
add_subdirectory(cpp)
add_subdirectory(lua)
add_subdirectory(networking)
add_subdirectory(tracing)
endif()
