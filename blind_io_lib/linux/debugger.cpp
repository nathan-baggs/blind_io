#include "debugger.h"

#include <format>
#include <memory>
#include <stdexcept>
#include <vector>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "auto_release.h"
#include "process.h"

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

}
