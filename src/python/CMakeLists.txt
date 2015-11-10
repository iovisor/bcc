# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

macro(symlink_file SRC DST)
  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${SRC} ${DST})
endmacro()

symlink_file(${CMAKE_CURRENT_SOURCE_DIR}/bcc ${CMAKE_CURRENT_BINARY_DIR}/bcc)

if(NOT PYTHON_CMD)
  set(PYTHON_CMD "python")
endif()

set(PIP_INSTALLABLE "${CMAKE_CURRENT_BINARY_DIR}/dist/bcc-${REVISION}.tar.gz")
configure_file(setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/setup.py @ONLY)
# build the pip installable
add_custom_command(OUTPUT ${PIP_INSTALLABLE}
  COMMAND ${PYTHON_CMD} setup.py sdist
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bcc/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/setup.py
  )
add_custom_target(bcc_py ALL DEPENDS ${PIP_INSTALLABLE})

if(EXISTS "/etc/debian_version")
  set(PYTHON_FLAGS "${PYTHON_FLAGS} --install-layout deb")
endif()
install(CODE "execute_process(COMMAND ${PYTHON_CMD} setup.py install -f ${PYTHON_FLAGS}
  --prefix=${CMAKE_INSTALL_PREFIX} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})"
  COMPONENT python)
