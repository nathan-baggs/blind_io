add_executable(blind_io_cmd
    main.cpp
)

target_compile_features(blind_io_cmd PUBLIC cxx_std_23)
target_compile_options(blind_io_cmd PUBLIC /W4 /WX)
target_link_libraries(blind_io_cmd blind_io)
