////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "process.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include <Windows.h>

#include <Psapi.h>

namespace bio
{

Process::Process(std::uint32_t pid)
    : pid_(pid)
    , handle_(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_), ::CloseHandle)
{
    if (!handle_)
    {
        throw std::runtime_error("failed to open process");
    }
}

std::uint32_t Process::pid() const
{
    return pid_;
}

std::string Process::name() const
{
    HMODULE module{};
    DWORD bytes_needed = 0;

    if (::K32EnumProcessModules(handle_, &module, sizeof(module), &bytes_needed) == 0)
    {
        throw std::runtime_error("failed to get first module");
    }

    std::string module_name(MAX_PATH, '\0');
    const auto chars_written =
        ::K32GetModuleBaseNameA(handle_, module, module_name.data(), static_cast<DWORD>(module_name.size()));

    if (chars_written == 0)
    {
        throw std::runtime_error("failed to get module base name");
    }

    module_name.resize(chars_written);

    return module_name;
}

}