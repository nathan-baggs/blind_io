#include <algorithm>
#include <cstddef>
#include <limits>
#include <ranges>

extern "C"
{
__declspec(dllexport) void reverse_array_hook(int *arr, size_t len)
{
    arr[len - 1] = std::numeric_limits<int>::max();
}
}
