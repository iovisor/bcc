cmake_minimum_required(VERSION 3.0)

# This sample requires C++11 enabled.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Weffc++")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/usdt_sample_lib1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/usdt_sample_app1)
