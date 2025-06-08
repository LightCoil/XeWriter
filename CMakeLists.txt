cmake_minimum_required(VERSION 3.15)
project(xexwriter VERSION 1.0 LANGUAGES CXX)

# Require C++20 for char8_t, std::span, std::endian, etc.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_library(xexwriter STATIC xex_writer.cpp)
target_include_directories(xexwriter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(xexwriter PUBLIC OpenSSL::Crypto)

# Optionally build unit tests
option(BUILD_TESTING "Build unit tests" OFF)
if(BUILD_TESTING)
    enable_testing()
    find_package(GTest REQUIRED)
    add_executable(test_xex test_xex.cpp)
    target_link_libraries(test_xex PRIVATE xexwriter GTest::gtest_main)
    add_test(NAME xexwriter_tests COMMAND test_xex)
endif()
