////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "memory_region_protection.h"

namespace bio
{

/**
 * This class represents an allocated range of memory in a process.
 */
class MemoryRegion
{
  public:
    /**
     * Construct a new MemoryRegion object.
     *
     * @param address
     *   Start address (in process virtual address space) of region
     *
     * @param size
     *   Number of bytes in region.
     *
     * @param protection
     *   Flags representing memory protection properties.
     *
     * @param name
     *   Optional (platform specific) name for the region.
     */
    MemoryRegion(
        std::uintptr_t address,
        std::size_t size,
        MemoryRegionProtection protection,
        const std::string &name = {});

    /**
     * Address of region (in process virtual address space).
     *
     * @returns
     *   Address of region.
     */
    std::uintptr_t address() const;

    /**
     * Size (in bytes) of region.
     *
     * @returns
     *   Size of region.
     */
    std::size_t size() const;

    /**
     * Protection properties of region.
     *
     * @returns
     *   Protection properties
     */
    MemoryRegionProtection protection() const;

    /**
     * Get the (platform specific) name of the region, maybe empty.
     *
     * @returns
     *   Region name.
     */
    std::string name() const;

    /**
     * Check if this region has a given protection mask.
     *
     * @param protection
     *   The protection to test (can be multiples if combined).
     *
     * @returns
     *   True of region matches supplied protection, otherwise false.
     */
    bool test_protection(MemoryRegionProtection protection) const;

  private:
    /** Address of region (in process virtual address space). */
    std::uintptr_t address_;

    /** Size of region in bytes. */
    std::size_t size_;

    /** Protection properties. */
    MemoryRegionProtection protection_;

    /** Optional (platform specific) region name. */
    std::string name_;
};

}
