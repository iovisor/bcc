cmake_minimum_required(VERSION 3.0)
project(usdt_sample_lib1)

# Define variables.
set(USDT_SAMPLE_LIB1_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include CACHE STRING "USDT_SAMPLE_LIB1_INCLUDE_DIR" FORCE)
set(USDT_SAMPLE_LIB1_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src CACHE STRING "USDT_SAMPLE_LIB1_SRC_DIR" FORCE)
set(USDT_SAMPLE_LIB1_LINK_DIR ${CMAKE_CURRENT_BINARY_DIR} CACHE STRING "USDT_SAMPLE_LIB1_LINK_DIR" FORCE)
set(USDT_SAMPLE_LIB1_LIB ${PROJECT_NAME} CACHE STRING "USDT_SAMPLE_LIB1_LIB" FORCE)
set(USDT_SAMPLE_LIB1_GENERATED ${CMAKE_CURRENT_BINARY_DIR}/generated)

## Start - N.B. Following section only relevant when using systemtap-sdt-devel.

# Create usdt header file.
# N.B. ${USDT_SAMPLE_LIB1_INCLUDE_DIR}/usdt_sample_lib1/lib1_sdt.h must be removed manually in order for it to be (re-)created.
#  i.e. after making changes to libt_sdt.d
#add_custom_command(
#    OUTPUT ${USDT_SAMPLE_LIB1_INCLUDE_DIR}/usdt_sample_lib1/lib1_sdt.h
#    PRE_BUILD
#    COMMAND dtrace -h -s ${USDT_SAMPLE_LIB1_SRC_DIR}/lib1_sdt.d -o ${USDT_SAMPLE_LIB1_INCLUDE_DIR}/usdt_sample_lib1/lib1_sdt.h
#    COMMENT "Create usdt probes header file"
#)

# Create usdt object file.
#file(MAKE_DIRECTORY ${USDT_SAMPLE_LIB1_GENERATED})
#add_custom_command(
#    OUTPUT ${USDT_SAMPLE_LIB1_GENERATED}/lib1_sdt.o
#    PRE_BUILD
#    COMMAND dtrace -G -s ${USDT_SAMPLE_LIB1_SRC_DIR}/lib1_sdt.d -o ${USDT_SAMPLE_LIB1_GENERATED}/lib1_sdt.o
#    COMMENT "Create usdt probes object file"
#)

## End

include_directories(
    ${USDT_SAMPLE_LIB1_INCLUDE_DIR}
    # For folly StaticTracepoint.h:
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../tests/python/include
)

add_library( ${PROJECT_NAME} SHARED
## Only relevant when using systemtap-sdt-devel
#    ${USDT_SAMPLE_LIB1_INCLUDE_DIR}/usdt_sample_lib1/lib1_sdt.h
#    ${USDT_SAMPLE_LIB1_GENERATED}/lib1_sdt.o
    ${USDT_SAMPLE_LIB1_SRC_DIR}/lib1.cpp
)
