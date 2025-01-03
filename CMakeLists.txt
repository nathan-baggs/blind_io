cmake_minimum_required(VERSION 3.22)

project(
    blind_io
    VERSION "0.1.0"
    DESCRIPTION ""
    LANGUAGES C CXX)

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0)
FetchContent_GetProperties(googletest)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(FETCHCONTENT_QUIET FALSE)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone
    GIT_TAG 5.0.1)
FetchContent_MakeAvailable(capstone)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(blind_io_lib)
add_subdirectory(blind_io_cmd)
add_subdirectory(support_corpus)

enable_testing()
include(CTest)
add_subdirectory(tests)
