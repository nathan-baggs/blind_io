////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "process.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <locale>
#include <memory>
#include <optional>
#include <print>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#define NOMINMAX
#include <Windows.h>

#include <Psapi.h>
#include <tlhelp32.h>

#include "auto_release.h"
#include "memory_region.h"
#include "memory_region_protection.h"
#include "process_utils.h"

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

/**
 * Helper function to convert a library memory protection value into a win32 type.
 *
 * @param protection
 *   Protection presented as a library type.
 *
 * @returns
 *   Win32 protection value.
 */
DWORD to_native(bio::MemoryRegionProtection protection)
{
    if (protection == bio::MemoryRegionProtection::EXECUTE)
    {
        return PAGE_EXECUTE;
    }
    if (protection == bio::MemoryRegionProtection::READ)
    {
        return PAGE_READONLY;
    }
    if (protection == (bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE))
    {
        return PAGE_READWRITE;
    }
    if (protection == (bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE))
    {
        return PAGE_EXECUTE_READ;
    }
    if (protection ==
        (bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE | bio::MemoryRegionProtection::EXECUTE))
    {
        return PAGE_EXECUTE_READWRITE;
    }

    return 0;
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
        ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, impl_->pid),
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
    return read(region.address(), region.size());
}

std::vector<std::uint8_t> Process::read(std::uintptr_t address, std::size_t size) const
{
    std::vector<std::uint8_t> mem(size);

    if (::ReadProcessMemory(impl_->handle, reinterpret_cast<void *>(address), mem.data(), mem.size(), nullptr) == 0)
    {
        throw std::runtime_error("failed to read memory region");
    }

    return mem;
}

void Process::write(const MemoryRegion &region, std::span<const std::uint8_t> data) const
{
    assert(data.size() <= region.size());
    write(region.address(), data);
}

void Process::write(std::uintptr_t address, std::span<const std::uint8_t> data) const
{
    if (::WriteProcessMemory(impl_->handle, reinterpret_cast<void *>(address), data.data(), data.size(), nullptr) == 0)
    {
        std::println("{}", ::GetLastError());
        throw std::runtime_error("failed to write memory");
    }
}

void Process::set_protection(std::uintptr_t address, MemoryRegionProtection new_protection) const
{
    const auto regions = memory_regions();
    const auto region = std::ranges::find_if(
        regions,
        [address](const auto &region)
        { return std::clamp(address, region.address(), region.address() + region.size()) == address; });

    if (region == std::ranges::cend(regions))
    {
        throw std::runtime_error("address not in any region");
    }

    DWORD old_protection{};

    if (::VirtualProtectEx(
            impl_->handle,
            reinterpret_cast<void *>(region->address()),
            region->size(),
            to_native(new_protection),
            &old_protection) == 0)
    {
        std::println("{}", ::GetLastError());
        throw std::runtime_error("failed to set protection");
    }
}

MemoryRegion Process::allocate(std::size_t bytes) const
{
    const auto address =
        ::VirtualAllocEx(impl_->handle, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (address == nullptr)
    {
        throw std::runtime_error("failed to allocate memory");
    }

    return {
        reinterpret_cast<std::uintptr_t>(address),
        bytes,
        MemoryRegionProtection::READ | MemoryRegionProtection::WRITE | MemoryRegionProtection::EXECUTE};
}

std::optional<MemoryRegion> Process::allocate(std::uintptr_t address, std::size_t bytes) const
{
    const auto alloc_address = ::VirtualAllocEx(
        impl_->handle, reinterpret_cast<void *>(address), bytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    return alloc_address == nullptr
               ? std::nullopt
               : std::make_optional<MemoryRegion>(
                     reinterpret_cast<std::uintptr_t>(alloc_address),
                     bytes,
                     MemoryRegionProtection::READ | MemoryRegionProtection::WRITE | MemoryRegionProtection::EXECUTE);
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

void Process::load_library(const std::filesystem::path &path) const
{
    // allocate some space in the remote process to store the path to the library
    const auto path_mem = allocate(4096u);
    const auto path_str = std::filesystem::absolute(path).string();
    write(path_mem, std::span{reinterpret_cast<const std::uint8_t *>(path_str.data()), path_str.size()});

    // create a remote thread to load the library
    AutoRelease<HANDLE> thread{::CreateRemoteThread(
        impl_->handle,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(::LoadLibraryA),
        reinterpret_cast<void *>(path_mem.address()),
        0,
        nullptr)};
    if (!thread)
    {
        throw std::runtime_error("failed to create thread");
    }
}

HookContext Process::set_hook(std::uintptr_t insert_address, std::uintptr_t hook_address) const
{
    // we need to allocate some memory in the remote process to store the detour code
    // it needs to be no more than a 32 bite signed relative jump away
    const auto max_offset = std::numeric_limits<std::int32_t>::max();
    const auto max_page_offset = ((max_offset / 4096) * 4096) - (4096 * 2);
    const auto insert_address_page = (insert_address / 4096) * 4096;

    std::uintptr_t detour_address{};

    // keep trying to allocate memory at different offsets until we find one that works
    for (auto offset = -max_offset; offset < max_page_offset; offset += 4096)
    {
        if (const auto alloc = allocate(insert_address_page + offset, 4096u); alloc)
        {
            detour_address = alloc->address();
            break;
        }
    }

    if (detour_address == 0u)
    {
        throw std::runtime_error("failed to allocate detour memory");
    }

    // mov r10, hook_address
    // jmp r10
    const std::uint8_t detour_code[] = {
        0x49,
        0xBA,
        (hook_address >> 0) & 0xFF,
        (hook_address >> 8) & 0xFF,
        (hook_address >> 16) & 0xFF,
        (hook_address >> 24) & 0xFF,
        (hook_address >> 32) & 0xFF,
        (hook_address >> 40) & 0xFF,
        (hook_address >> 48) & 0xFF,
        (hook_address >> 56) & 0xFF,
        0x41,
        0xFF,
        0xE2};

    std::println("writing detour to {:#x}", detour_address);
    write(detour_address, detour_code);

    if (::FlushInstructionCache(impl_->handle, reinterpret_cast<const void *>(detour_address), sizeof(detour_code)) ==
        0)
    {
        throw std::runtime_error("failed to flush instruction cache");
    }

    // account for the fact that the offset includes the size of the jmp instruction
    detour_address = detour_address - insert_address - 5;

    // jmp detour_address
    const std::uint8_t hook_code[] = {
        0xe9,
        (detour_address >> 0) & 0xFF,
        (detour_address >> 8) & 0xFF,
        (detour_address >> 16) & 0xFF,
        (detour_address >> 24) & 0xFF};

    const auto original_bytes = read(insert_address, sizeof(hook_code));

    std::println("writing hook to {:#x}", insert_address);
    write(insert_address, hook_code);

    if (::FlushInstructionCache(impl_->handle, reinterpret_cast<const void *>(insert_address), sizeof(hook_code)) == 0)
    {
        throw std::runtime_error("failed to flush instruction cache");
    }

    return {insert_address, hook_address, original_bytes};
}

void Process::remove_hook(const HookContext &context) const
{
    std::println("removing hook {:#x} {:#x}", context.insert_address, context.original_bytes.size());
    write(context.insert_address, context.original_bytes);

    if (::FlushInstructionCache(
            impl_->handle, reinterpret_cast<const void *>(context.insert_address), context.original_bytes.size()) == 0)
    {
        throw std::runtime_error("failed to flush instruction cache");
    }
}

std::vector<RemoteFunction> Process::address_of_function(std::string_view name) const
{
    std::vector<RemoteFunction> functions{};

    std::vector<HMODULE> modules(1024u);
    DWORD bytes_needed = 0u;

    // enumerate all modules in the process
    do
    {
        // windows won't tell us how many modules are loaded in the process, so we keep trying with larger buffers
        // until we think we've got them all
        modules.resize(modules.size() * 2u);

        if (::K32EnumProcessModules(
                impl_->handle, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &bytes_needed) ==
            0)
        {
            throw std::runtime_error("failed to get process modules");
        }
    } while (bytes_needed >= modules.size() * sizeof(HMODULE));

    // need to resize to the actual number of modules
    modules.resize(bytes_needed / sizeof(HMODULE));

    // parse all modules and search for our function in their exports
    for (const auto module : modules)
    {
        // get the full path of the module
        char module_name[MAX_PATH];
        if (::GetModuleFileNameExA(impl_->handle, module, module_name, sizeof(module_name)) == 0)
        {
            throw std::runtime_error("failed to get module name");
        }

        // shorten the module name to just the file name
        const auto last_slash = std::string_view{module_name}.find_last_of('\\');
        const std::string module_name_short(std::string_view{module_name}.substr(last_slash + 3));

        ::MODULEINFO module_info{};
        if (::K32GetModuleInformation(impl_->handle, module, &module_info, sizeof(module_info)) == 0)
        {
            throw std::runtime_error("failed to get module information");
        }

        const auto module_start = reinterpret_cast<std::uintptr_t>(module_info.lpBaseOfDll);

        // read the dos header and verify it
        const auto dos_header = read_object<::IMAGE_DOS_HEADER>(*this, module_start);
        if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        {
            throw std::runtime_error("invalid dos header");
        }

        // read the nt header and verify it
        const auto nt_image_header = read_object<::IMAGE_NT_HEADERS64>(*this, module_start + dos_header.e_lfanew);
        if (nt_image_header.Signature != IMAGE_NT_SIGNATURE)
        {
            throw std::runtime_error("failed to read nt image header");
        }

        if (nt_image_header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            throw std::runtime_error("failed to read optional header");
        }

        // get the address of the module export directory
        const auto export_directory_virtual_address =
            nt_image_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        const auto export_directory =
            read_object<::IMAGE_EXPORT_DIRECTORY>(*this, module_start + export_directory_virtual_address);

        // get the offsets to the various tables needed to resolve function names
        const auto function_name_table =
            read_objects<DWORD>(*this, module_start + export_directory.AddressOfNames, export_directory.NumberOfNames);
        const auto function_address_table = read_objects<DWORD>(
            *this, module_start + export_directory.AddressOfFunctions, export_directory.NumberOfFunctions);
        const auto function_ordinal_table = read_objects<WORD>(
            *this, module_start + export_directory.AddressOfNameOrdinals, export_directory.NumberOfNames);

        // go through each function name entry and resolve the function name itself
        for (auto index = 0u; const auto function_name_offset : function_name_table)
        {
            std::string function_name{};

            // the actual function names are stored contiguously in an array of null terminated strings, so no real
            // option but to read them character by character
            for (;;)
            {
                const auto next_char =
                    read_object<char>(*this, module_start + function_name_offset + function_name.length());
                if (next_char == '\0')
                {
                    break;
                }

                function_name.push_back(next_char);
            }

            if (function_name == name)
            {
                // do the index to ordinal lookup to address lookup dance in order to get the actual function offset
                const auto address = module_start + function_address_table[function_ordinal_table[index]];
                functions.push_back({module_name_short, function_name, address});
            }

            ++index;
        }
    }

    return functions;
}
}
