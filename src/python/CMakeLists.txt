# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

macro(symlink_file SRC DST)
  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${SRC} ${DST})
endmacro()

symlink_file(${CMAKE_CURRENT_SOURCE_DIR}/bcc ${CMAKE_CURRENT_BINARY_DIR}/bcc)

if(NOT PYTHON_CMD)
  set(PYTHON_CMD "python")
endif()

configure_file(setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/setup.py @ONLY)
if(EXISTS "/etc/debian_version")
  set(PYTHON_FLAGS "${PYTHON_FLAGS} --install-layout deb")
endif()

foreach(PY_CMD ${PYTHON_CMD})
  string(REPLACE "/" "-" PY_CMD_ESCAPED ${PY_CMD})

  set(PIP_INSTALLABLE "${CMAKE_CURRENT_BINARY_DIR}/dist-${PY_CMD_ESCAPED}/bcc-${REVISION}.tar.gz")
  # build the pip installable
  add_custom_command(OUTPUT ${PIP_INSTALLABLE}
    COMMAND ${PY_CMD} setup.py sdist --dist-dir dist-${PY_CMD_ESCAPED}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bcc/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/setup.py
    )
  add_custom_target(bcc_py_${PY_CMD_ESCAPED} ALL DEPENDS ${PIP_INSTALLABLE})

  install(CODE "execute_process(COMMAND ${PY_CMD} setup.py install -f ${PYTHON_FLAGS}
    --prefix=${CMAKE_INSTALL_PREFIX} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})"
    COMPONENT python)
endforeach()
