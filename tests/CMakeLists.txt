
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

mark_as_advanced(BUILD_GMOCK BUILD_GTEST gtest_hide_internal_symbols)

add_executable(unit_tests
    auto_release_tests.cpp
    memory_region_protection_tests.cpp
)

target_link_libraries(unit_tests blind_io gmock_main)
gtest_discover_tests(unit_tests)