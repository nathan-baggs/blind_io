////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "process_utils.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <ranges>
#include <vector>

namespace bio
{

std::vector<std::uint32_t> get_pids()
{
    std::vector<std::uint32_t> pids{};

    for (const auto &entry : std::filesystem::directory_iterator("/proc") |
                                 std::views::filter([](const auto &e) { return e.is_directory(); }))
    {
        const auto pid = entry.path().filename().string();
        if (std::ranges::all_of(pid, isdigit))
        {
            pids.push_back(std::stoi(pid));
        }
    }

    return pids;
}

}