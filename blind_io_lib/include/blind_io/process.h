////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <Windows.h>

#include "auto_release.h"
#include "memory_region.h"

namespace bio
{

/**
 * This class represents a view onto a running process and provides methods for interacting with it.
 */
class Process
{
  public:
    /**
     * Construct a new Process object from a pid.
     *
     * @param pid
     *   Pid of process.
     */
    Process(std::uint32_t pid);

    /**
     * Get process pid.
     *
     * @returns
     *   Process pid.
     */
    std::uint32_t pid() const;

    /**
     * Get process name.
     *
     * @returns
     *   Process name.
     */
    std::string name() const;

    /**
     * Get all current memory regions fro the process.
     *
     * @returns
     *   Process memory regions.
     */
    std::vector<MemoryRegion> memory_regions() const;

  private:
    /** Process pid. */
    std::uint32_t pid_;

    /** Win32 windows handle to process. */
    AutoRelease<HANDLE> handle_;
};

}
