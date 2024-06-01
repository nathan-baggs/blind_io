////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "process_utils.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "process.h"

namespace bio
{

std::vector<Process> find_process(std::string_view name)
{
    std::vector<Process> procs{};

    for (const auto pid : get_pids())
    {
        try
        {
            Process proc{pid};
            if (proc.name() == name)
            {
                procs.push_back(std::move(proc));
            }
        }
        catch (std::runtime_error &)
        {
        }
    }

    return procs;
}

void replace_memory(
    const Process &process,
    const MemoryRegion &region,
    std::span<const std::uint8_t> find,
    std::span<const std::uint8_t> replace,
    std::optional<std::size_t> num_occurrences)
{
    assert(find.size() == replace.size());
    assert(region.test_protection(MemoryRegionProtection::READ | MemoryRegionProtection::WRITE));

    auto mem = process.read(region);
    auto mem_span = std::span(mem);

    auto remaining_occurrences = num_occurrences.value_or(std::numeric_limits<std::size_t>::max());

    while (!mem_span.empty() && (remaining_occurrences > 0))
    {
        if (const auto found = std::ranges::search(mem_span, find); !found.empty())
        {
            const auto begin = std::ranges::distance(std::cbegin(mem_span), std::cbegin(found));

            std::memcpy(mem_span.data() + begin, replace.data(), replace.size());

            process.write(region, mem);

            mem_span = mem_span.subspan(begin);
            --remaining_occurrences;
        }
        else
        {
            break;
        }
    }
}

}