set(FILES http-parse-complete.c http-parse-simple.c README.md)
set(PROGRAMS http-parse-complete.py http-parse-simple.py)
install(FILES ${FILES} DESTINATION share/bcc/examples/networking/http_filter)
install(PROGRAMS ${PROGRAMS} DESTINATION share/bcc/examples/networking/http_filter)
