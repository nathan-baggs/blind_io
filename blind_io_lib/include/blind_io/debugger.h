#pragma once

#include <memory>
#include <string_view>

#include "process.h"
#include "registers.h"

namespace bio
{

/**
 * Class that encapsulated a process being debugged,
 */
class Debugger
{
  public:
    /**
     * Construct a new Debugger object with a Process. Will attach to all threads within the process and suspend them.
     *
     * @param process
     *   The process to debug.
     */
    Debugger(Process process);

    /**
     * Destructor, will resume all threads.
     */
    ~Debugger();

    /**
     * Get the registers for a specific tid.
     *
     * @param tid
     *   Id of thread to get registers of.
     *
     * @returns
     *   Current register value of thread.
     */
    Registers registers(std::uint32_t tid) const;

    /**
     * Allocate some memory into the process. Will be read, write executable.
     *
     * @param bytes
     *   The number of bytes to allocate, should be a multiple of the page size.
     *
     * @returns
     *   A region describing the new allocated memory.
     */
    MemoryRegion allocate(std::size_t bytes) const;

    /**
     * Load a library into the running process.
     *
     * @param path
     *   Path of library to load.
     */
    void load_library(std::string_view path) const;

  private:
    /** The process being debugged. */
    Process process_;

    struct implementation;

    /** Pointer to implementation. */
    std::unique_ptr<implementation> impl_;
};

}
