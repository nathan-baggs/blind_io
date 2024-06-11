#include "debugger.h"

#include <format>
#include <iostream>
#include <memory>
#include <print>
#include <stdexcept>
#include <vector>

#include <errno.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "auto_release.h"
#include "process.h"

namespace
{

struct AutoRestoreRegisters
{
    AutoRestoreRegisters(std::uint32_t pid, ::user_regs_struct saved_regs, ::user_regs_struct new_regs)
        : pid(pid)
        , saved_regs(saved_regs)
        , new_regs(new_regs)
    {
        if (::ptrace(PTRACE_SETREGS, pid, nullptr, &new_regs) == -1)
        {
            throw std::runtime_error("failed to set registers");
        }
    }

    ~AutoRestoreRegisters()
    {
        if (::ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs) == -1)
        {
            std::println(std::cerr, "failed to restore registers");
        }
    }

    std::uint32_t pid;
    ::user_regs_struct saved_regs;
    ::user_regs_struct new_regs;
};

struct AutoRestoreInstructions
{
    AutoRestoreInstructions(std::uint32_t pid, std::uintptr_t address, long saved_instructions, long new_instructions)
        : pid(pid)
        , address(address)
        , saved_instructions(saved_instructions)
        , new_instructions(new_instructions)
    {
        if (::ptrace(PTRACE_POKETEXT, pid, address, new_instructions) == -1)
        {
            throw std::runtime_error("failed to write new instructions");
        }
    }

    ~AutoRestoreInstructions()
    {
        if (::ptrace(PTRACE_POKETEXT, pid, address, saved_instructions) == -1)
        {
            std::println(std::cerr, "failed to restore instructions");
        }
    }

    std::uint32_t pid;
    std::uintptr_t address;
    long saved_instructions;
    long new_instructions;
};

}

namespace bio
{

struct Debugger::implementation
{
    std::vector<AutoRelease<std::uint32_t>> suspended_threads;
};

Debugger::Debugger(Process process)
    : process_(std::move(process))
    , impl_(std::make_unique<implementation>())
{
    // we will try and trace all threads of the process, this will cause them to all be suspended
    // in the event of an error we will resume any threads we managed to suspend

    for (const auto &thread : process_.threads())
    {
        // attach ourselves as the tracer to the thread, this will send SIGSTOP to the thread
        if (::ptrace(PTRACE_ATTACH, thread.tid(), 0, 0) == -1)
        {
            throw std::runtime_error(std::format("failed to trace tid: {}", thread.tid()));
        }

        // we need to wait for the thread to be stopped, bit it might need to process other signals before it gets to
        // out SIGSTOP, so we keep injecting signals back into the process until it stops
        for (;;)
        {
            // wait for the thread to process a signal
            int wstatus = 0;
            if (::waitpid(thread.tid(), &wstatus, 0) == -1)
            {
                throw std::runtime_error(std::format("failed to wait for tid: {}", thread.tid()));
            }

            if (WIFSTOPPED(wstatus))
            {
                // it's a stop signal (hopefully ours!), create an AutoRelease to auto detach
                impl_->suspended_threads.emplace_back(
                    thread.tid(), [](const auto tid) { ::ptrace(PTRACE_DETACH, tid, 0, 0); });
                break;
            }
            else
            {
                // it's another signal, inject it back and allow the thread to process it
                if (::ptrace(PTRACE_CONT, thread.tid(), 0, WSTOPSIG(wstatus)) == -1)
                {
                    throw std::runtime_error(std::format("failed to continue tid: {}", thread.tid()));
                }
            }
        }
    }
}

Debugger::~Debugger() = default;

Registers Debugger::registers(std::uint32_t tid) const
{
    // get the registers in a platform specific format
    ::user_regs_struct regs{};
    if (::ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1)
    {
        throw std::runtime_error(std::format("failed to get registers for tid: {}", tid));
    }

    return {
        .rax = regs.rax,
        .rbx = regs.rbx,
        .rcx = regs.rcx,
        .rdx = regs.rdx,
        .rsi = regs.rsi,
        .rdi = regs.rdi,
        .rsp = regs.rsp,
        .rbp = regs.rbp,
        .rip = regs.rip,
        .r8 = regs.r8,
        .r9 = regs.r9,
        .r10 = regs.r10,
        .r11 = regs.r11,
        .r12 = regs.r12,
        .r13 = regs.r13,
        .r14 = regs.r14,
        .r15 = regs.r15,
    };
}

MemoryRegion Debugger::allocate(std::size_t bytes) const
{
    // process is suspended here so grab the current register state
    ::user_regs_struct saved_regs{};
    if (::ptrace(PTRACE_GETREGS, process_.pid(), nullptr, &saved_regs) == -1)
    {
        throw std::runtime_error(std::format("failed to get registers for tid: {}", process_.pid()));
    }

    // find an executable region of memory
    const auto regions = process_.memory_regions();
    const auto executable_region = std::ranges::find_if(
        regions,
        [](const auto &e)
        { return ((e.protection() & MemoryRegionProtection::EXECUTE) == MemoryRegionProtection::EXECUTE); });

    if (executable_region == std::ranges::cend(regions))
    {
        throw std::runtime_error("no executable region");
    }

    // save off the first word of the executable section
    errno = 0;
    const auto saved_instructions = ::ptrace(PTRACE_PEEKTEXT, process_.pid(), executable_region->address(), nullptr);
    if (errno != 0)
    {
        throw std::runtime_error("failed to get instructions");
    }

    // replace the executable section with:
    //   syscall  ; execute a syscall
    //   int3     ; suspend process and return to debugger
    //   nop      ; padding
    //   nop
    //   nop
    //   nop
    //   nop
    const long hook_instructions = 0x9090909090cc050f;
    if (::ptrace(PTRACE_POKETEXT, process_.pid(), executable_region->address(), hook_instructions) == -1)
    {
        throw std::runtime_error("failed to write hook instructions");
    }

    // write hook instructions to process
    AutoRestoreInstructions release_instructions{
        process_.pid(), executable_region->address(), saved_instructions, hook_instructions};

    // modify the saved registers so that they are in the correct state to perform a mmap syscall
    auto syscall_reg = saved_regs;
    syscall_reg.rip = executable_region->address();
    syscall_reg.rax = 0x9;
    syscall_reg.rdi = 0x0;
    syscall_reg.rsi = bytes;
    syscall_reg.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    syscall_reg.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    syscall_reg.r8 = -1;
    syscall_reg.r9 = 0;

    // set registers of process
    AutoRestoreRegisters restore_regs{process_.pid(), saved_regs, syscall_reg};

    if (::ptrace(PTRACE_CONT, process_.pid(), 0, 0) == -1)
    {
        throw std::runtime_error("failed to continue");
    }

    // wait for process to hit the int3
    int wstatus = 0;
    if (::waitpid(process_.pid(), &wstatus, 0) == -1)
    {
        throw std::runtime_error("failed to wait for process");
    }

    // if the process got any signal other than a SIGTRAP then something has gone wrong
    if (WSTOPSIG(wstatus) != SIGTRAP)
    {
        throw std::runtime_error("failed to stop on trap");
    }

    // get the register state from the process, the mmap result will be in rax
    const auto result_reg = registers(process_.pid());
    const auto mmap_res = result_reg.rax;
    if (reinterpret_cast<void *>(mmap_res) == MAP_FAILED)
    {
        throw std::runtime_error("failed to inject mmap");
    }

    return {
        mmap_res,
        bytes,
        MemoryRegionProtection::READ | MemoryRegionProtection::WRITE | MemoryRegionProtection::EXECUTE};
}

}
