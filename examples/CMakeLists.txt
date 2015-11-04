set(EXAMPLE_PROGRAMS hello_world.py)
install(PROGRAMS ${EXAMPLE_PROGRAMS} DESTINATION share/bcc/examples)

add_subdirectory(networking)
add_subdirectory(tracing)
