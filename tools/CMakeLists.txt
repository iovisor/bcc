set(PROGRAMS biolatency biosnoop funccount funclatency hardirqs killsnoop
  opensnoop pidpersec softirqs syncsnoop tcpaccept tcpconnect vfscount vfsstat)
set(C_FILES pidpersec.c vfscount.c vfsstat.c)
set(EXAMPLE_FILES biolatency_example.txt funclatency_example.txt
  killsnoop_example.txt pidpersec_example.txt syncsnoop_example.txt
  tcpconnect_example.txt vfsstat_example.txt biosnoop_example.txt
  funccount_example.txt hardirqs_example.txt opensnoop_example.txt
  softirqs_example.txt tcpaccept_example.txt vfscount_example.txt)
install(PROGRAMS ${PROGRAMS} DESTINATION share/bcc/tools)
install(FILES ${C_FILES} DESTINATION share/bcc/tools)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/tools/doc)
