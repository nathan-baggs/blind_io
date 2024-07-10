////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "process.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <print>
#include <ranges>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <sys/uio.h>

#include "memory_region.h"
#include "memory_region_protection.h"
#include "utils.h"

using namespace std::literals;

namespace
{

/**
 * Helper function to convert a linux memory protection value into our internal library type.
 *
 * @param protection_str
 *   Linux protection string.
 *
 * @returns
 *   Protection presented as a library type.
 */
bio::MemoryRegionProtection to_native(std::string_view protection_str)
{
    auto protection = bio::MemoryRegionProtection::NO_PROTECTION;

    if (std::ranges::search(protection_str, "r"sv))
    {
        protection |= bio::MemoryRegionProtection::READ;
    }

    if (std::ranges::search(protection_str, "w"sv))
    {
        protection |= bio::MemoryRegionProtection::WRITE;
    }

    if (std::ranges::search(protection_str, "x"sv))
    {
        protection |= bio::MemoryRegionProtection::EXECUTE;
    }

    return protection;
}

}

namespace bio
{

struct Process::implementation
{
    std::uint32_t pid;
};

Process::Process(std::uint32_t pid)
    : impl_(std::make_unique<implementation>())
{
    impl_->pid = pid;
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
    const auto status = read_file(std::format("/proc/{}/status", impl_->pid));

    // name of the process has the following format in the status file:
    // Name:\tname\n
    static const auto name_line = "Name:\t"sv;
    const auto name_line_start = status.find(name_line);
    const auto name_line_end = status.find('\n', name_line_start + name_line.length());

    return status.substr(name_line_start + name_line.length(), name_line_end - name_line_start - name_line.length());

    return {};
}

std::vector<MemoryRegion> Process::memory_regions() const
{
    std::vector<MemoryRegion> regions{};

    const auto maps = read_file(std::format("/proc/{}/maps", impl_->pid));

    // memory region has following format in maps file:
    // start-end prot ...
    std::regex map_regex{"([a-f0-9]+)-([a-f0-9]+)\\s([rwxp-]{4}).*\\s+(.*)$"};

    for (const auto &line :
         std::views::split(maps, '\n') |
             std::views::transform([](const auto &e)
                                   { return std::string(std::ranges::cbegin(e), std::ranges::cend(e)); }))
    {
        std::smatch matches{};

        if (std::regex_search(line, matches, map_regex))
        {
            if (matches.size() == 5)
            {
                const auto start = std::stoll(matches[1].str(), nullptr, 16);
                const auto end = std::stoll(matches[2].str(), nullptr, 16);

                regions.push_back(
                    {static_cast<std::uintptr_t>(start),
                     static_cast<std::size_t>(end - start),
                     to_native(matches[3].str()),
                     matches[4].str()});
            }
        }
    }

    return regions;
}

std::vector<std::uint8_t> Process::read(const MemoryRegion &region) const
{
    std::vector<std::uint8_t> mem(region.size());

    ::iovec local{.iov_base = mem.data(), .iov_len = mem.size()};
    ::iovec remote{.iov_base = reinterpret_cast<void *>(region.address()), .iov_len = region.size()};

    if (::process_vm_readv(impl_->pid, &local, 1, &remote, 1, 0) != static_cast<ssize_t>(region.size()))
    {
        throw std::runtime_error("failed to read memory region");
    }

    return mem;
}

void Process::write(const MemoryRegion &region, std::span<const std::uint8_t> data) const
{
    assert(data.size() <= region.size());

    ::iovec local{.iov_base = const_cast<void *>(reinterpret_cast<const void *>(data.data())), .iov_len = data.size()};
    ::iovec remote{.iov_base = reinterpret_cast<void *>(region.address()), .iov_len = data.size()};

    if (::process_vm_writev(impl_->pid, &local, 1, &remote, 1, 0) != static_cast<ssize_t>(data.size()))
    {
        throw std::runtime_error("failed to write memory");
    }
}

std::vector<Thread> Process::threads() const
{
    std::vector<Thread> tids{};

    for (const auto &entry : std::filesystem::directory_iterator(std::format("/proc/{}/task", impl_->pid)) |
                                 std::views::filter([](const auto &e) { return e.is_directory(); }))
    {
        const auto tid = entry.path().filename().string();
        if (std::ranges::all_of(tid, isdigit))
        {
            tids.push_back(Thread{static_cast<std::uint32_t>(std::stoi(tid))});
        }
    }

    return tids;
}

}
