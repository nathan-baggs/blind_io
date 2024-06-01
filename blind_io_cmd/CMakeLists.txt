add_executable(blind_io_cmd
    main.cpp
)

target_compile_features(blind_io_cmd PUBLIC cxx_std_23)

if(WIN32)
    target_compile_options(blind_io_cmd PUBLIC /W4 /WX)
elseif(LINUX)
    target_compile_options(blind_io_cmd PUBLIC -Werror -Wall -Wextra -pedantic)
endif()

target_link_libraries(blind_io_cmd blind_io)
