set(FILES biolatency.8 biosnoop.8 funccount.8 funclatency.8 hardirqs.8
  killsnoop.8 opensnoop.8 pidpersec.8 softirqs.8 syncsnoop.8 tcpaccept.8
  tcpconnect.8 vfscount.8 vfsstat.8)
install(FILES ${FILES} DESTINATION share/bcc/man/man8)
