configure_file(wrapper.sh.in "${CMAKE_CURRENT_BINARY_DIR}/wrapper.sh" @ONLY)

set(TEST_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/wrapper.sh)

add_subdirectory(cc)
