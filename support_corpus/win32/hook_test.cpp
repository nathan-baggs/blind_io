#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <print>
#include <ranges>
#include <string>

#include <Windows.h>

extern "C"
{

__declspec(dllexport) void reverse_array(int *arr, size_t len)
{
    std::ranges::reverse(arr, arr + len);
}
}

int main()
{
    const auto reverse_lib = ::LoadLibraryA("support_corpus/win32/reverse_array_lib.dll");
    assert(reverse_lib != nullptr);

    const auto reverse_array_lib =
        reinterpret_cast<void (*)(int *, size_t)>(::GetProcAddress(reverse_lib, "reverse_array"));

    std::array<int, 5> arr = {1, 2, 3, 4, 5};

    reverse_array(arr.data(), arr.size());
    reverse_array_lib(arr.data(), arr.size());

    const auto str = arr                                                               //
                     | std::views::transform([](auto i) { return std::to_string(i); }) //
                     | std::views::join                                                //
                     | std::ranges::to<std::string>();

    std::println("address of reverse_array: {:#x}", reinterpret_cast<std::uintptr_t>(&reverse_array));
    std::println("address of reverse_array_lib: {:#x}", reinterpret_cast<std::uintptr_t>(reverse_array_lib));
    std::println("address of MessageBoxA: {:#x}", reinterpret_cast<std::uintptr_t>(&::MessageBoxA));

    for (;;)
    {
        ::MessageBoxA(nullptr, str.c_str(), "Reversed array", MB_OK);

        char c{};
        std::cin >> c;

        if (c == 'q')
        {
            break;
        }
    }
}
