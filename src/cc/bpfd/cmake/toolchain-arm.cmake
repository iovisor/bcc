# Copyright (c) Jazel Canseco, 2018
# Copyright (c) Adrian Ratiu, 2019
# Licensed under the Apache License, Version 2.0 (the "License")
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

if(NOT CMAKE_C_COMPILER)
  set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
endif()

if(NOT CMAKE_CXX_COMPILER)
  set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)
endif()

if(NOT CMAKE_FIND_ROOT_PATH)
  set(CMAKE_FIND_ROOT_PATH /usr/arm-linux-gnueabihf)
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
