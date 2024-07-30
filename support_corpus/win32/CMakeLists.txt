add_library(dll_main_write_file SHARED
    dll_main_write_file.cpp
)
target_compile_features(dll_main_write_file PUBLIC cxx_std_23)
target_compile_options(dll_main_write_file PUBLIC /W4 /WX)
target_link_options(dll_main_write_file PUBLIC /INCREMENTAL:NO)

add_library(hook_message_box SHARED
    hook_message_box.cpp
)
target_compile_features(hook_message_box PUBLIC cxx_std_23)
target_compile_options(hook_message_box PUBLIC /W4 /WX)
target_link_options(hook_message_box PUBLIC /INCREMENTAL:NO)

add_library(reverse_array_lib SHARED
    reverse_array_lib.cpp
)
target_compile_features(reverse_array_lib PUBLIC cxx_std_23)
target_compile_options(reverse_array_lib PUBLIC /W4 /WX)
target_link_options(reverse_array_lib PUBLIC /INCREMENTAL:NO)

add_library(reverse_array_hook_lib SHARED
    reverse_array_hook_lib.cpp
)
target_compile_features(reverse_array_hook_lib PUBLIC cxx_std_23)
target_compile_options(reverse_array_hook_lib PUBLIC /W4 /WX)
target_link_options(reverse_array_hook_lib PUBLIC /INCREMENTAL:NO)

add_executable(hook_test
    hook_test.cpp
)
target_compile_features(hook_test PUBLIC cxx_std_23)
target_compile_options(hook_test PUBLIC /W4 /WX)
target_link_options(hook_test PUBLIC /INCREMENTAL:NO)

