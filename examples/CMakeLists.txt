set(EXAMPLE_FILES hello_world.py task_switch.py task_switch.c simple_tc.py
                  simulation.py vlan_learning.py vlan_learning.c)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/examples)

add_subdirectory(distributed_bridge)
