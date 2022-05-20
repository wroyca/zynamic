cmake_minimum_required(VERSION 3.23.1 FATAL_ERROR)
project(Zynamic LANGUAGES CXX)

set(MASTER_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MASTER_PROJECT ON)
endif()

add_subdirectory(externals)
add_subdirectory(src)
