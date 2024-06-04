////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include <cassert>
#include <chrono>
#include <print>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string_view>
#include <thread>

#include "debugger.h"
#include "process.h"
#include "process_utils.h"

using namespace std::literals;

int main()
{
    auto procs = bio::find_process("vim");
    assert(procs.size() == 1);

    auto &proc = procs.front();

    auto tid = proc.pid();

    std::println("{} -> {}", proc.name(), proc.pid());

    for (const auto &thread : proc.threads())
    {
        std::println("tid: {}", thread.tid());
    }

    bio::Debugger dbg{std::move(proc)};

    [[maybe_unused]] const auto regs = dbg.registers(tid);

    std::this_thread::sleep_for(10s);

    // for (const auto &proc : bio::find_process("vim"))
    //{
    //     std::println("{} -> {}", proc.name(), proc.pid());
    //     for (const auto &region : proc.memory_regions())
    //     {
    //         if (region.test_protection(bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE))
    //         {
    //             bio::replace_memory(proc, region, "vorpal", "VORPAL");
    //         }
    //     }
    // }

    return 0;
}