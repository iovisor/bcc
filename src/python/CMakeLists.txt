# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

file(GLOB_RECURSE PYTHON_SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*.py)
file(GLOB_RECURSE PYTHON_INCLUDES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*.py.in)

foreach(PY_CMD ${PYTHON_CMD})
  string(REPLACE "/" "-" PY_CMD_ESCAPED ${PY_CMD})
  set(PY_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bcc-${PY_CMD_ESCAPED})

  foreach(PY_SRC ${PYTHON_SOURCES})
    configure_file(${PY_SRC} ${PY_DIRECTORY}/${PY_SRC} COPYONLY)
  endforeach()

  foreach(PY_INC ${PYTHON_INCLUDES})
    string(REPLACE ".py.in" ".py" PY_INC_REPLACED ${PY_INC})
    configure_file(${PY_INC} ${PY_DIRECTORY}/${PY_INC_REPLACED} @ONLY)
  endforeach()

  set(PIP_INSTALLABLE "${PY_DIRECTORY}/dist/bcc-${REVISION}-py3-none-any.whl")
  add_custom_command(
    OUTPUT ${PIP_INSTALLABLE}
    COMMAND ${PY_CMD} -m build --wheel ${PY_DIRECTORY}
    WORKING_DIRECTORY ${PY_DIRECTORY}
    DEPENDS ${PYTHON_SOURCES} ${PYTHON_INCLUDES}
    COMMENT "Building ${PIP_INSTALLABLE} for ${PY_CMD}"
  )
  add_custom_target(bcc_py_${PY_CMD_ESCAPED} ALL DEPENDS ${PIP_INSTALLABLE})

  if(NOT PYTHON_PREFIX)
     set(PYTHON_PREFIX ${CMAKE_INSTALL_PREFIX})
  endif()

  message(STATUS "Install ${PIP_INSTALLABLE} for ${PY_CMD}.")
  install(
    CODE "
      execute_process(
        COMMAND ${PY_CMD} -m pip install --force-reinstall --prefix=${PYTHON_PREFIX} ${PIP_INSTALLABLE}
	WORKING_DIRECTORY ${PY_DIRECTORY})"
    COMPONENT python)
endforeach()
