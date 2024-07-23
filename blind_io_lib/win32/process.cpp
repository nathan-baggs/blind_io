////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "process.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <locale>
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

std::vector<RemoteFunction> Process::address_of_function(std::string_view name) const
{
    std::vector<RemoteFunction> functions{};

    std::vector<HMODULE> modules(1024u);
    DWORD bytes_needed = 0u;

    // enumerate all modules in the process
    do
    {
        // windows won'tm tell us how many modules are loaded in the process, so we keep trying with larger buffers
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

        // shroten the module name to just the file name
        const auto last_slash = std::string_view{module_name}.find_last_of('\\');
        const std::string module_name_short(std::string_view{module_name}.substr(last_slash + 1));

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

            // the actual function names are stored contigulously in an array of null terminated strings, so no real
            // option but to read them characte by character
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
