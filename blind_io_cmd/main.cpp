////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include <print>
#include <stdexcept>

#include "process.h"
#include "process_utils.h"

int main()
{
    for (const auto &proc : bio::find_process("firefox.exe"))
    {
        std::println("{} -> {}", proc.name(), proc.pid());
    }

    return 0;
}