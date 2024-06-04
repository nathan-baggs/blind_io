#pragma once

#include <cstdint>
#include <memory>

namespace bio
{

/**
 * Class encapsulating a running thread.
 */
class Thread
{
  public:
    /**
     * Construct  anew Thread object from a tid.
     *
     * @param tid
     *   Id of thread.
     */
    explicit Thread(std::uint32_t tid);

    ~Thread();
    Thread(Thread &&);
    Thread &operator=(Thread &&);

    /**
     * Get process tid.
     *
     * @returns
     *   Tid of process.
     */
    std::uint32_t tid() const;

  private:
    struct implementation;

    /** Pointer to implementation. */
    std::unique_ptr<implementation> impl_;
};

}
