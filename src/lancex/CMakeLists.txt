cmake_minimum_required(VERSION 2.8.10)

if(NOT TARGET kapi)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
#set(CMAKE_DISABLE_SOURCE_CHANGES  ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)

project(lancex C CXX)

#
include(FindPkgConfig)
pkg_check_modules(openssl REQUIRED openssl>=1.0.1)
pkg_check_modules(jansson REQUIRED jansson>=2.5)
#cxxflags cflags

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pedantic")

file(GLOB CPP_FILES *.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(${PROJECT_NAME} STATIC ${CPP_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} ${openssl_LIBRARIES} ${jansson_LIBRARIES} pthread)

else()
message("-- dev : lancex is included more then once")
endif()
