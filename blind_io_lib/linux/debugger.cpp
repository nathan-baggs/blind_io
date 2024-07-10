#include "debugger.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <iostream>
#include <memory>
#include <print>
#include <ranges>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "auto_release.h"
#include "process.h"
#include "utils.h"

using namespace std::literals;

namespace
{

// raii wrappers for storing and restoring various pieces of process state

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

/**
 * Helper function to execute assembly instruction in a remote process. Will restore state afterwards and, in the event
 * of an error, will best attempt to cleanup the process back to it's original state.
 *
 * @param process
 *   The process to execute into.
 *
 * @param saved_regs
 *   The original register state that should be restored after the injection (or after an error).
 *
 * @param exec_regs
 *   The state the registers of the process should be in for executing the instructions. It is the callers
 *   responsibility to set rip.
 *
 * @param instructions
 *   The machine word length set of instructions to inject and execute. It is the callers responsibility to ensure int3
 *   is called.
 *
 * @param executable_region
 *   The (executable) region of memory that the instructions should be written into.
 *
 * @returns
 *   Registers after instructions were executed.
 */
::user_regs_struct execute_remote_instruction(
    const bio::Process &process,
    const ::user_regs_struct &saved_regs,
    const ::user_regs_struct &exec_regs,
    long instructions,
    std::uintptr_t executable_region)
{
    // save off the first word of the executable section
    errno = 0;
    const auto saved_instructions = ::ptrace(PTRACE_PEEKTEXT, process.pid(), executable_region, nullptr);
    if (errno != 0)
    {
        throw std::runtime_error("failed to get instructions");
    }

    if (::ptrace(PTRACE_POKETEXT, process.pid(), executable_region, instructions) == -1)
    {
        throw std::runtime_error("failed to write hook instructions");
    }

    // write hook instructions to process
    AutoRestoreInstructions release_instructions{process.pid(), executable_region, saved_instructions, instructions};

    // set registers of process
    AutoRestoreRegisters restore_regs{process.pid(), saved_regs, exec_regs};

    if (::ptrace(PTRACE_CONT, process.pid(), 0, 0) == -1)
    {
        throw std::runtime_error("failed to continue");
    }

    // wait for process to hit the int3
    int wstatus = 0;
    if (::waitpid(process.pid(), &wstatus, 0) == -1)
    {
        throw std::runtime_error("failed to wait for process");
    }

    // if the process got any signal other than a SIGTRAP then something has gone wrong
    if (WSTOPSIG(wstatus) != SIGTRAP)
    {
        throw std::runtime_error("failed to stop on trap");
    }

    ::user_regs_struct result_regs{};
    if (::ptrace(PTRACE_GETREGS, process.pid(), nullptr, &result_regs) == -1)
    {
        throw std::runtime_error(std::format("failed to get registers for pid: {}", process.pid()));
    }

    return result_regs;
}

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

    // replace the executable section with:
    //   syscall  ; execute a syscall
    //   int3     ; suspend process and return to debugger
    //   nop      ; padding
    //   nop
    //   nop
    //   nop
    //   nop
    const long hook_instructions = 0x9090909090cc050f;

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

    const auto res_reg =
        execute_remote_instruction(process_, saved_regs, syscall_reg, hook_instructions, executable_region->address());

    // get the register state from the process, the mmap result will be in rax
    if (reinterpret_cast<void *>(res_reg.rax) == MAP_FAILED)
    {
        throw std::runtime_error("failed to inject mmap");
    }

    return {
        res_reg.rax,
        bytes,
        MemoryRegionProtection::READ | MemoryRegionProtection::WRITE | MemoryRegionProtection::EXECUTE};
}

void Debugger::load_library(std::string_view path) const
{
    auto regions = process_.memory_regions();

    // find where libc is loaded into the remote process
    const auto libc_region =
        std::ranges::find_if(regions, [](const auto &e) { return e.name().contains("libc.so"sv); });
    if (libc_region == std::ranges::cend(regions))
    {
        throw std::runtime_error("failed to find libc");
    }

    // read libc from disk
    const auto elf_str = read_file(libc_region->name());
    const auto *elf = elf_str.data();

    // parse out the elf header
    ::Elf64_Ehdr elf_header{};
    std::memcpy(&elf_header, elf, sizeof(elf_header));
    if (std::memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0)
    {
        throw std::runtime_error("not an ELF");
    }

    // get the section headers
    std::vector<::Elf64_Shdr> section_headers(elf_header.e_shnum);
    std::memcpy(section_headers.data(), elf + elf_header.e_shoff, sizeof(::Elf64_Shdr) * section_headers.size());

    // find the dynamic symbol section header
    const auto dynsym = std::ranges::find_if(section_headers, [](const auto &e) { return e.sh_type == SHT_DYNSYM; });
    if (dynsym == std::ranges::cend(section_headers))
    {
        throw std::runtime_error("cannot find dynsym");
    }

    // get all the symbols from the dynsym
    std::vector<::Elf64_Sym> sym_table(dynsym->sh_size / sizeof(::Elf64_Sym));
    std::memcpy(sym_table.data(), elf + dynsym->sh_offset, dynsym->sh_size);

    // get the string table for synsym
    const auto dynstr = section_headers[dynsym->sh_link];

    // copy all the strings from the table for easier parsing
    std::vector<char> str_table(dynstr.sh_size);
    std::memcpy(str_table.data(), elf + dynstr.sh_offset, str_table.size());

    std::uintptr_t dlopen_addr{};

    // search for dlopen
    for (const auto &symbol : sym_table)
    {
        if (std::string_view(str_table.data() + symbol.st_name) == "dlopen"sv)
        {
            // found it, resolve the address of it in the process memory (offset + address of libc)
            dlopen_addr = symbol.st_value + libc_region->address();
            break;
        }
    }

    // we want to call dlopen(path) in the remote process, so allocate some space for path and copy in the actual dll
    // path we want to call
    const auto path_mem = allocate(4096u);
    auto path_buffer = process_.read(path_mem);
    std::memcpy(path_buffer.data(), path.data(), path.length());
    process_.write(path_mem, path_buffer);

    // ensure stack alignment by creating a new stack
    const auto stack = allocate(4096u);

    regions = process_.memory_regions();

    // process is suspended here so grab the current register state
    ::user_regs_struct saved_regs{};
    if (::ptrace(PTRACE_GETREGS, process_.pid(), nullptr, &saved_regs) == -1)
    {
        throw std::runtime_error(std::format("failed to get registers for tid: {}", process_.pid()));
    }

    // find an executable region of memory
    const auto executable_region = std::ranges::find_if(
        regions,
        [](const auto &e)
        { return ((e.protection() & MemoryRegionProtection::EXECUTE) == MemoryRegionProtection::EXECUTE); });

    if (executable_region == std::ranges::cend(regions))
    {
        throw std::runtime_error("no executable region");
    }

    // replace the executable section with:
    //   nop       ; padding
    //   nop
    //   nop
    //   call rbx  ; address of dlopen will be in rbx
    //   int3      ; suspend process and return to debugger
    //   nop       ; padding
    //   nop
    const long hook_instructions = 0x909090ccd3ff9090;

    // modify the saved registers so that they are in the correct state to call dlopen
    auto inject_reg = saved_regs;
    inject_reg.rip = executable_region->address() + 2; // account for the fact that the kernel might rewind us two
                                                       // instructions if process was executing a syscall
    inject_reg.rbx = dlopen_addr;                      // address of dlopen
    inject_reg.rdi = path_mem.address();               // address of dll path in remote process
    inject_reg.rsi = RTLD_NOW;                         // dlopen arg
    inject_reg.rsp = stack.address() + stack.size();   // use our new stack
    inject_reg.rbp = inject_reg.rsp;                   // use our new stack

    execute_remote_instruction(process_, saved_regs, inject_reg, hook_instructions, executable_region->address());
}

}
