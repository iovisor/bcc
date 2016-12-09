set(EXAMPLE_FILES README.txt simulation.py tc_neighbor_sharing.c)
set(EXAMPLE_PROGRAMS tc_neighbor_sharing.py)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/examples/networking/neighbor_sharing)
install(PROGRAMS ${EXAMPLE_PROGRAMS} DESTINATION share/bcc/examples/networking/neighbor_sharing)
