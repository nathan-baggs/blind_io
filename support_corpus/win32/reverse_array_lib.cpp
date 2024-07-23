#include <algorithm>
#include <cstddef>
#include <ranges>
#include <string>
#include <string_view>

extern "C"
{
    __declspec(dllexport) void reverse_array(int *arr, size_t len)
    {
        std::ranges::reverse(arr, arr + len);
    }
}
