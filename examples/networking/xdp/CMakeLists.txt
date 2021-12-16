file(GLOB PY_FILES *.py)
install(PROGRAMS ${PY_FILES} DESTINATION share/bcc/examples/networking/xdp)
