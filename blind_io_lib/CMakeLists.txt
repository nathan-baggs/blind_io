add_library(blind_io
    memory_region.cpp
    memory_region_protection.cpp
    process_utils.cpp
    utils.cpp
)

add_library(blind_io::blind_io ALIAS blind_io)

target_compile_features(blind_io PUBLIC cxx_std_23)

if(WIN32)
    target_compile_options(blind_io PUBLIC /W4 /WX)
    add_subdirectory(win32)
elseif(LINUX)
    target_compile_options(blind_io PUBLIC -Wall -Werror -Wextra -pedantic)
    add_subdirectory(linux)
endif()

target_include_directories(
    blind_io
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/blind_io_lib/include/blind_io>
    $<INSTALL_INTERFACE:include/blind_io>
)
