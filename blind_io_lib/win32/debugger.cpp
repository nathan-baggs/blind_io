#include "debugger.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <print>
#include <stdexcept>
#include <string_view>

#include <Windows.h>

#include "auto_release.h"
#include "memory_region.h"
#include "memory_region_protection.h"
#include "process.h"
#include "registers.h"

namespace bio
{

struct Debugger::implementation
{
};

Debugger::Debugger(Process process)
    : process_(std::move(process))
    , impl_(std::make_unique<implementation>())
{
    if (::DebugActiveProcess(process_.pid()) == 0)
    {
        throw std::runtime_error("failed to debug process");
    }
}

Debugger::~Debugger()
{
    if (::DebugActiveProcessStop(process_.pid()) == 0)
    {
        std::println(std::cerr, "failed to detach from process");
    }
}

Registers Debugger::registers(std::uint32_t tid) const
{
    // convert the thread id into a handle
    const auto thread_handle = AutoRelease<::HANDLE>{::OpenThread(THREAD_GET_CONTEXT, FALSE, tid), ::CloseHandle};
    if (!thread_handle)
    {
        throw std::runtime_error("failed to open thread");
    }

    // get the context of the thread
    ::CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    if (::GetThreadContext(thread_handle, &context) == 0)
    {
        throw std::runtime_error("failed to get thread context");
    }

    return {
        .rax = context.Rax,
        .rbx = context.Rbx,
        .rcx = context.Rcx,
        .rdx = context.Rdx,
        .rsi = context.Rsi,
        .rdi = context.Rdi,
        .rsp = context.Rsp,
        .rbp = context.Rbp,
        .rip = context.Rip,
        .r8 = context.R8,
        .r9 = context.R9,
        .r10 = context.R10,
        .r11 = context.R11,
        .r12 = context.R12,
        .r13 = context.R13,
        .r14 = context.R14,
        .r15 = context.R15,
    };
}

MemoryRegion Debugger::allocate([[maybe_unused]] std::size_t bytes) const
{
    return {0x0, 0x0, MemoryRegionProtection::NO_PROTECTION};
}

void Debugger::load_library([[maybe_unused]] std::string_view path) const
{
}
}
