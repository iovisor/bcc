cmake_minimum_required(VERSION 3.12)
project(usdt_sample_app1)

add_executable( ${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

target_link_libraries( ${PROJECT_NAME}
    usdt_sample_lib1
    pthread
)
