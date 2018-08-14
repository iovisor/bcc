set(FILES README.md chord.png monitor.c simulation.py vxlan.jpg)
set(PROGRAMS main.py monitor.py setup.sh traffic.sh)
install(FILES ${FILES} DESTINATION share/doc/bcc/examples/networking/tunnel_monitor)
install(PROGRAMS ${PROGRAMS} DESTINATION share/doc/bcc/examples/networking/tunnel_monitor)
