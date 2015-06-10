# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

macro(symlink_file SRC DST)
  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${SRC} ${DST})
endmacro()

symlink_file(${CMAKE_CURRENT_SOURCE_DIR}/bpf ${CMAKE_CURRENT_BINARY_DIR}/bpf)

set(PIP_INSTALLABLE "${CMAKE_CURRENT_BINARY_DIR}/dist/bpf-${REVISION}.tar.gz")
configure_file(setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/setup.py @ONLY)
# build the pip installable
add_custom_command(OUTPUT ${PIP_INSTALLABLE}
  COMMAND python setup.py sdist
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/setup.py
  )
add_custom_target(bpf_py ALL DEPENDS ${PIP_INSTALLABLE})
install(CODE "execute_process(COMMAND python setup.py install -f
  --prefix=${CMAKE_INSTALL_PREFIX} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})")
