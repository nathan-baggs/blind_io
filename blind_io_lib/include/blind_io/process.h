////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "memory_region.h"
#include "thread.h"

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

    ~Process();
    Process(Process &&);
    Process &operator=(Process &&);

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

    /**
     * Read a region of memory.
     *
     * @param region
     *   The region to read.
     *
     * @returns
     *   The read region.
     */
    std::vector<std::uint8_t> read(const MemoryRegion &region) const;

    /**
     * Write data to the supplied region.
     *
     * @param region
     *   The region to write to.
     *
     * @param data
     *   The data to write (must not be larger than region).
     */
    void write(const MemoryRegion &region, std::span<const std::uint8_t> data) const;

    /**
     * Get all the threads of the current process.
     *
     * @returns
     *   Collection of threads for the process.
     */
    std::vector<Thread> threads() const;

  private:
    struct implementation;

    /** Pointer to implementation. */
    std::unique_ptr<implementation> impl_;
};

}
