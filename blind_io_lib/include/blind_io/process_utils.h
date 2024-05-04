////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "process.h"

namespace bio
{

/**
 * Get the pids for all currently running processes.
 *
 * @returns
 *   Collection of pids.
 */
std::vector<std::uint32_t> get_pids();

/**
 * Find processes matching a given name
 *
 * @returns
 *   Collection of processes, empty if none were found (or could be opened).
 */
std::vector<Process> find_process(std::string_view name);

}
