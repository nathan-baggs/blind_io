////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include <print>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string_view>

#include "process.h"
#include "process_utils.h"

using namespace std::literals;

int main()
{
    for (const auto &proc : bio::find_process("Notepad.exe"))
    {
        std::println("{} -> {}", proc.name(), proc.pid());
        for (const auto &region : proc.memory_regions())
        {
            if (region.test_protection(bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE))
            {
                bio::replace_memory(proc, region, L"vorpal", L"VORPAL", 1);
            }
        }
    }

    return 0;
}