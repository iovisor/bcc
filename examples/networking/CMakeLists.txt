set(EXAMPLE_FILES simulation.py)
set(EXAMPLE_PROGRAMS simple_tc.py)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/examples/networking)
install(PROGRAMS ${EXAMPLE_PROGRAMS} DESTINATION share/bcc/examples/networking)

add_subdirectory(distributed_bridge)
add_subdirectory(neighbor_sharing)
add_subdirectory(vlan_learning)
