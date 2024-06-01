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
#include <fstream>
#include <memory>
#include <print>
#include <ranges>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "memory_region.h"
#include "memory_region_protection.h"

using namespace std::literals;

namespace
{

/**
 * Helper function to read file.
 *
 * @param path
 *   Path of file to read.
 *
 * @returns
 *   Contents of file as a string.
 */
std::string read_file(const std::string &path)
{
    const std::ifstream file{path};
    if (!file.is_open() || !file.good() || file.bad())
    {
        throw std::runtime_error("failed to read file");
    }

    std::stringstream strm{};
    strm << file.rdbuf();

    return strm.str();
}

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
    std::regex map_regex{"([a-f0-9]+)-([a-f0-9]+)\\s([rwxp-]{4}).*"};

    for (const auto &line :
         std::views::split(maps, '\n') |
             std::views::transform([](const auto &e)
                                   { return std::string(std::ranges::cbegin(e), std::ranges::cend(e)); }))
    {
        std::smatch matches{};

        if (std::regex_search(line, matches, map_regex))
        {
            if (matches.size() == 4)
            {
                const auto start = std::stoll(matches[1].str(), nullptr, 16);
                const auto end = std::stoll(matches[2].str(), nullptr, 16);

                regions.push_back(
                    {static_cast<std::uintptr_t>(start),
                     static_cast<std::size_t>(end - start),
                     to_native(matches[3].str())});
            }
        }
    }

    return regions;
}

std::vector<std::uint8_t> Process::read([[maybe_unused]] const MemoryRegion &region) const
{
    return {};
}

void Process::write([[maybe_unused]] const MemoryRegion &region, [[maybe_unused]] std::span<const std::uint8_t> data)
    const
{
}

}