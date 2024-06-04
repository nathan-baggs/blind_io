#pragma once

#include <memory>

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

  private:
    /** The process being debugged. */
    Process process_;

    struct implementation;

    /** Pointer to implementation. */
    std::unique_ptr<implementation> impl_;
};

}
