#include "thread.h"

#include <cstdint>
#include <memory>

namespace bio
{

struct Thread::implementation
{
    std::uint32_t tid;
};

Thread::Thread(std::uint32_t tid)
    : impl_(std::make_unique<implementation>())
{
    impl_->tid = tid;
}

Thread::~Thread() = default;
Thread::Thread(Thread &&) = default;
Thread &Thread::operator=(Thread &&) = default;

std::uint32_t Thread::tid() const
{
    return impl_->tid;
}

}
