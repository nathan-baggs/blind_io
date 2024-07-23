#include <filesystem>
#include <fstream>

#include <Windows.h>

extern "C"
{
    BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
    {
        if (fdwReason == DLL_PROCESS_ATTACH)
        {
            return TRUE;
        }

        const std::filesystem::path path{"C:\\Users\\Public\\test.txt"};
        std::ofstream file{path};

        file << "Hello, World!" << std::endl;

        return TRUE;
    }
}
