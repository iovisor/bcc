cmake_minimum_required(VERSION 3.12)
project(usdt_sample_lib1)

# Define variables.
set(USDT_SAMPLE_LIB1_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include CACHE STRING "USDT_SAMPLE_LIB1_INCLUDE_DIR" FORCE)
set(USDT_SAMPLE_LIB1_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src CACHE STRING "USDT_SAMPLE_LIB1_SRC_DIR" FORCE)
set(USDT_SAMPLE_LIB1_LINK_DIR ${CMAKE_CURRENT_BINARY_DIR} CACHE STRING "USDT_SAMPLE_LIB1_LINK_DIR" FORCE)
set(USDT_SAMPLE_LIB1_LIB ${PROJECT_NAME} CACHE STRING "USDT_SAMPLE_LIB1_LIB" FORCE)
set(USDT_SAMPLE_LIB1_GENERATED ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(USDT_SAMPLE_SDT_HEADER ${USDT_SAMPLE_LIB1_SRC_DIR}/lib1_sdt.h)
set(USDT_SAMPLE_SDT_OBJECT ${USDT_SAMPLE_LIB1_GENERATED}/lib1_sdt.o)
set(USDT_SAMPLE_SDT_PROBES ${USDT_SAMPLE_LIB1_SRC_DIR}/lib1_sdt.d)

add_library( ${PROJECT_NAME} SHARED
    ${USDT_SAMPLE_LIB1_SRC_DIR}/lib1.cpp
)

target_include_directories( ${PROJECT_NAME}
    PRIVATE
        # For folly StaticTracepoint.h:
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../tests/python/include
    PUBLIC
        ${USDT_SAMPLE_LIB1_INCLUDE_DIR}
)

target_link_libraries( ${PROJECT_NAME}
    ${USDT_SAMPLE_SDT_OBJECT}
)

## Start - N.B. Following section is relevant for when using systemtap-sdt-devel to define the probes.

# Create usdt header file.
add_custom_target( ${PROJECT_NAME}_HDR_CLEAN
   COMMAND rm -f ${USDT_SAMPLE_SDT_HEADER}
   COMMENT "Remove generated header"
)
add_custom_target( ${PROJECT_NAME}_HDR
   COMMAND dtrace -h -s ${USDT_SAMPLE_SDT_PROBES} -o ${USDT_SAMPLE_SDT_HEADER}
   COMMENT "Create usdt probes header file"
)
add_dependencies(${PROJECT_NAME}_HDR ${PROJECT_NAME}_HDR_CLEAN)

# Create usdt object file.
add_custom_target( ${PROJECT_NAME}_CLEAN
   COMMAND rm -rf ${USDT_SAMPLE_LIB1_GENERATED} && mkdir -p ${USDT_SAMPLE_LIB1_GENERATED}
   COMMENT "Recreate usdt probes generated folder"
)
add_custom_target( ${PROJECT_NAME}_OBJ
   COMMAND dtrace -G -s ${USDT_SAMPLE_SDT_PROBES} -o ${USDT_SAMPLE_SDT_OBJECT}
   COMMENT "Create usdt probes object file"
)
add_dependencies(${PROJECT_NAME}_OBJ ${PROJECT_NAME}_CLEAN)

add_dependencies(${PROJECT_NAME} ${PROJECT_NAME}_HDR ${PROJECT_NAME}_OBJ)

## End
