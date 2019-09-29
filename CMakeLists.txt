cmake_minimum_required(VERSION 3.10)
include(CheckSymbolExists)
include(TestBigEndian)

project(carafe)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-O2 -g -Wall")
file(GLOB SOURCES "main.cpp")

TEST_BIG_ENDIAN(BIGENDIAN)
IF(${BIGENDIAN})
     ADD_DEFINITIONS(-DBIGENDIAN)
ELSE(${BIGENDIAN})
     ADD_DEFINITIONS(-DLITTLEENDIAN)
ENDIF(${BIGENDIAN})

check_symbol_exists("arc4random_buf" "stdlib.h" HAVE_ARC4RANDOM_BUF)
if (HAVE_ARC4RANDOM_BUF)
    add_definitions(-DHAVE_ARC4RANDOM_BUF)
endif()

check_symbol_exists("getrandom" "sys/random.h" HAVE_GETRANDOM)
if (HAVE_GETRANDOM)
    add_definitions(-DHAVE_GETRANDOM)
endif()

add_executable(carafe ${SOURCES})
target_link_libraries(carafe microhttpd)
