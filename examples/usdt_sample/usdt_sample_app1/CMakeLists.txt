cmake_minimum_required(VERSION 3.0)
project(usdt_sample_app1)

include_directories(
    ${USDT_SAMPLE_LIB1_INCLUDE_DIR}
)

link_directories(
    ${USDT_SAMPLE_LIB1_LINK_DIR}
)

add_executable( ${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

target_link_libraries( ${PROJECT_NAME}
    ${USDT_SAMPLE_LIB1_LIB}
    pthread
)
