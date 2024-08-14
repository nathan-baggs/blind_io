////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory_region.h"
#include "memory_region_protection.h"
#include "thread.h"

namespace bio
{

/**
 * This struct represents a remote function in a process.
 */
struct RemoteFunction
{
    /** The library name the function is in. */
    std::string library_name;

    /** The function name. */
    std::string name;

    /** The address of the function. */
    std::uintptr_t address;
};

struct HookContext
{
    std::uintptr_t insert_address;
    std::uintptr_t hook_address;
    std::vector<std::uint8_t> original_bytes;
};

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
     * Read a region of memory.
     *
     * @param address
     *   The address (in the process) to read from.
     *
     * @param size
     *   The size of the region to read in bytes.
     *
     * @returns
     *   The read region.
     */
    std::vector<std::uint8_t> read(std::uintptr_t address, std::size_t size) const;

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
     * Write data to the supplied address.
     *
     * @param address
     *   The address to write to.
     *
     * @param data
     *   The data to write.
     */
    void write(std::uintptr_t address, std::span<const std::uint8_t> data) const;

    /**
     * Set the protection of a memory region.
     *
     * @param address
     *   The address of the region to set the protection of.
     *
     * @param new_protection
     *   The new protection to set.
     */
    void set_protection(std::uintptr_t address, MemoryRegionProtection new_protection) const;

    /**
     * Allocate a region of memory in the process.
     *
     * @param bytes
     *   The size of the region to allocate in bytes.
     *
     * @returns
     *   The allocated region.
     */
    MemoryRegion allocate(std::size_t bytes) const;

    /**
     * Try and allocate a region of memory in the process at a given address.
     *
     * @param address
     *   The address to allocate the region at.
     *
     * @param bytes
     *   The size of the region to allocate in bytes.
     *
     * @returns
     *   The allocated region.
     */
    std::optional<MemoryRegion> allocate(std::uintptr_t address, std::size_t bytes) const;

    /**
     * Get all the threads of the current process.
     *
     * @returns
     *   Collection of threads for the process.
     */
    std::vector<Thread> threads() const;

    /**
     * Load a library into the process.
     *
     * @param path
     *   The path to the library to load.
     */
    void load_library(const std::filesystem::path &path) const;

    /**
     * Set a hook in the process.
     *
     * @param insert_address
     *   The address to insert the hook at.
     *
     * @param hook_address
     *   The address of the hook function.
     */
    HookContext set_hook(std::uintptr_t insert_address, std::uintptr_t hook_address) const;

    void remove_hook(const HookContext &context) const;

    /**
     * Find the address of a function in the process.
     *
     * Note that this function will search all loaded libraries in the process for the function, so may return multiple
     * results.
     *
     * @param name
     *   The name of the function to search for.
     *
     * @returns
     *   Collection of remote functions.
     */
    std::vector<RemoteFunction> address_of_function(std::string_view name) const;

  private:
    struct implementation;

    /** Pointer to implementation. */
    std::unique_ptr<implementation> impl_;
};

}
