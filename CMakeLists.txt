cmake_minimum_required(VERSION 3.10)
project(carafe)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-O2 -g -Wall")
file(GLOB SOURCES "main.cpp")

add_executable(carafe ${SOURCES})
target_link_libraries(carafe microhttpd)
