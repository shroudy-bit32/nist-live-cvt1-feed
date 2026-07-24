cmake_minimum_required(VERSION 3.15)
project(cvt_carve LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(cvt_carve MODULE src/module.cpp)

target_include_directories(cvt_carve PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
  target_compile_options(cvt_carve PRIVATE /O2 /EHsc)
else()
  target_compile_options(cvt_carve PRIVATE -O3 -DNDEBUG)
endif()

install(TARGETS cvt_carve DESTINATION .)
