set(EXAMPLE_FILES bitehist.c bitehist_example.txt disksnoop.c
  disksnoop_example.txt task_switch.c tcpv4connect tcpv4connect_example.txt
  vfsreadlat.c vfsreadlat_example.txt)
set(EXAMPLE_PROGRAMS bitehist.py disksnoop.py task_switch.py trace_fields.py vfsreadlat.py)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/examples/tracing)
install(PROGRAMS ${EXAMPLE_PROGRAMS} DESTINATION share/bcc/examples/tracing)
