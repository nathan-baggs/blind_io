////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include <cassert>
#include <chrono>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#include "debugger.h"
#include "disassembler.h"
#include "instruction.h"
#include "memory_region_protection.h"
#include "process.h"
#include "process_utils.h"

using namespace std::literals;

int main()
{
    try
    {
        auto procs = bio::find_process("hook_test.exe");
        assert(procs.size() == 1);

        auto &proc = procs.front();

        const std::filesystem::path hook_dll_path{".\\support_corpus\\win32\\hook_message_box.dll"};
        proc.load_library(hook_dll_path);

        const auto message_box_functions = proc.address_of_function("MessageBoxA");
        assert(message_box_functions.size() == 1u);
        const auto message_box_function = message_box_functions.front();

        const auto hooked_message_box_functions = proc.address_of_function("hooked_MessageBoxA");
        assert(hooked_message_box_functions.size() == 1u);
        const auto hooked_message_box_function = hooked_message_box_functions.front();

        proc.set_protection(
            message_box_function.address,
            bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE |
                bio::MemoryRegionProtection::EXECUTE);

        const auto message_box_asm = proc.read(message_box_function.address, 30);
        const bio::Disassembler disassembler{};

        for (const auto &instruction : disassembler.disassemble(message_box_asm))
        {
            std::println("{}", instruction);
        }

        //// const std::uint8_t ret_asm[] = {0xc3};
        //// proc.write(message_box_function.address, ret_asm);

        const auto hook_context = proc.set_hook(message_box_function.address, hooked_message_box_function.address);

        std::println("sleeping");
        std::this_thread::sleep_for(5s);
        proc.remove_hook(hook_context);
    }
    catch (const std::runtime_error &err)
    {
        std::println(std::cerr, "{}", err.what());
    }

    // std::println("{} -> {}", proc.name(), proc.pid());

    // for (const auto &thread : proc.threads())
    //{
    //     std::println("tid: {}", thread.tid());
    // }

    // bio::Debugger dbg{std::move(proc)};
    // dbg.load_library("/tmp/libtest.so");

    return 0;
}
