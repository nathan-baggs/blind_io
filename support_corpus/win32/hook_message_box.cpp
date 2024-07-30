#include <Windows.h>

#include <print>

extern "C"
{

__declspec(dllexport) int hooked_MessageBoxA(HWND, LPCSTR lpText, LPCSTR, UINT)
{
    std::println("hooked MessageBoxA {}", lpText);

    return 0;
}
}
