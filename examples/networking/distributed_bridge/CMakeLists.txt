set(EXAMPLE_FILES simulation.py tunnel.c tunnel_mesh.c)
set(EXAMPLE_PROGRAMS main.py tunnel_mesh.py tunnel.py)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/examples/networking/distributed_bridge)
install(PROGRAMS ${EXAMPLE_PROGRAMS} DESTINATION share/bcc/examples/networking/distributed_bridge)
