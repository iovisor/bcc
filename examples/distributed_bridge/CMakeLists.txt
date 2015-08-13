set(EXAMPLE_FILES main.py simulation.py tunnel_mesh.py tunnel.py
                  tunnel.c tunnel_mesh.c)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/examples/distributed_bridge)
