cmake_minimum_required(VERSION 3.14)
project(xexwriter_freeboot VERSION 1.0 LANGUAGES CXX)

# C++20/23 fallback
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++23" HAS_CXX23)
if(HAS_CXX23)
  set(CMAKE_CXX_STANDARD 23)
else()
  set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

add_library(xexwriter
    xex_writer.hpp
    xex_writer.cpp
)
target_include_directories(xexwriter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(xexwriter PUBLIC OpenSSL::Crypto)

option(ENABLE_TESTS "Build unit tests" ON)
if(ENABLE_TESTS)
  enable_testing()
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/release-1.12.1.zip
  )
  FetchContent_MakeAvailable(googletest)
  add_executable(test_xex
      tests/test_xex.cpp
  )
  target_link_libraries(test_xex PRIVATE xexwriter gtest_main)
  add_test(NAME XexWriterTests COMMAND test_xex)
endif()
