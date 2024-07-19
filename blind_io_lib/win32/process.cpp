////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "process.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <print>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <Windows.h>

#include <Psapi.h>
#include <tlhelp32.h>

#include "auto_release.h"
#include "memory_region.h"
#include "memory_region_protection.h"

namespace
{

/**
 * Helper function to convert a win32 memory protection value into our internal library type.
 *
 * @param protection
 *   Win32 protection value.
 *
 * @returns
 *   Protection presented as a library type.
 */
bio::MemoryRegionProtection to_internal(DWORD protection)
{
    switch (protection)
    {
        case PAGE_EXECUTE: return bio::MemoryRegionProtection::EXECUTE;
        case PAGE_READONLY: return bio::MemoryRegionProtection::READ;
        case PAGE_READWRITE: return bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE;
        case PAGE_EXECUTE_READ: return bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE;
        case PAGE_EXECUTE_READWRITE:
            return bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE |
                   bio::MemoryRegionProtection::EXECUTE;
    }

    // win32 has more types than we care about, so default to NO_PROTECTION
    return bio::MemoryRegionProtection::NO_PROTECTION;
}

}

namespace bio
{

struct Process::implementation
{
    std::uint32_t pid;

    AutoRelease<HANDLE> handle;
};

Process::Process(std::uint32_t pid)
    : impl_(std::make_unique<implementation>())
{
    impl_->pid = pid;
    impl_->handle = AutoRelease<HANDLE>{
        ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, impl_->pid),
        ::CloseHandle};
    if (!impl_->handle)
    {
        throw std::runtime_error("failed to open process");
    }
}

Process::~Process() = default;
Process::Process(Process &&) = default;
Process &Process::operator=(Process &&) = default;

std::uint32_t Process::pid() const
{
    return impl_->pid;
}

std::string Process::name() const
{
    HMODULE module{};
    DWORD bytes_needed = 0;

    if (::K32EnumProcessModules(impl_->handle, &module, sizeof(module), &bytes_needed) == 0)
    {
        throw std::runtime_error("failed to get first module");
    }

    std::string module_name(MAX_PATH, '\0');
    const auto chars_written =
        ::K32GetModuleBaseNameA(impl_->handle, module, module_name.data(), static_cast<DWORD>(module_name.size()));

    if (chars_written == 0)
    {
        throw std::runtime_error("failed to get module base name");
    }

    module_name.resize(chars_written);

    return module_name;
}

std::vector<MemoryRegion> Process::memory_regions() const
{
    std::vector<MemoryRegion> regions{};

    MEMORY_BASIC_INFORMATION mem_info{};
    std::byte *addr = 0x0;

    // keep calling VirtualQueryEx and move the addr each time, this will enumerate all regions
    // we loop until we error, however there is no way to differentiate between an actual error and just reaching the
    // end of the available regions, so return value is a best effort
    while (::VirtualQueryEx(impl_->handle, addr, &mem_info, sizeof(mem_info)) != 0)
    {
        if (mem_info.State == MEM_COMMIT)
        {
            regions.push_back(
                {reinterpret_cast<std::uintptr_t>(mem_info.BaseAddress),
                 mem_info.RegionSize,
                 to_internal(mem_info.Protect)});
        }

        // advance address by size of region
        addr += mem_info.RegionSize;
    }

    return regions;
}

std::vector<std::uint8_t> Process::read(const MemoryRegion &region) const
{
    std::vector<std::uint8_t> mem(region.size());

    if (::ReadProcessMemory(
            impl_->handle, reinterpret_cast<void *>(region.address()), mem.data(), mem.size(), nullptr) == 0)
    {
        throw std::runtime_error("failed to read memory region");
    }

    return mem;
}

void Process::write(const MemoryRegion &region, std::span<const std::uint8_t> data) const
{
    assert(data.size() <= region.size());

    if (::WriteProcessMemory(
            impl_->handle, reinterpret_cast<void *>(region.address()), data.data(), data.size(), nullptr) == 0)
    {
        throw std::runtime_error("failed to write memory");
    }
}

std::vector<Thread> Process::threads() const
{
    std::vector<Thread> threads{};

    // get a snapshot of all running threads
    AutoRelease<HANDLE> snapshot{::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, impl_->pid), ::CloseHandle};
    if (static_cast<HANDLE>(snapshot.get()) == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error("faield to get thread snapshot");
    }

    ::THREADENTRY32 thread_entry{};
    thread_entry.dwSize = sizeof(thread_entry);

    // get the first thread
    if (!::Thread32First(snapshot, &thread_entry))
    {
        throw std::runtime_error("failed to get first thread");
    }

    // loop through all threads searching for the ones that belong to our process
    do
    {
        if (thread_entry.th32OwnerProcessID == impl_->pid)
        {
            threads.push_back(Thread{thread_entry.th32ThreadID});
        }
    } while (::Thread32Next(snapshot, &thread_entry));

    return threads;
}
}
