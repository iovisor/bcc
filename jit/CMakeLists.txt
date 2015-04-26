
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto -fno-rtti")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/compat/include)

add_subdirectory(src)
