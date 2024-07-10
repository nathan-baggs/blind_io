////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "memory_region.h"

#include <string>

namespace bio
{

MemoryRegion::MemoryRegion(
    std::uintptr_t address,
    std::size_t size,
    MemoryRegionProtection protection,
    const std::string &name)
    : address_(address)
    , size_(size)
    , protection_(protection)
    , name_(name)
{
}

std::uintptr_t MemoryRegion::address() const
{
    return address_;
}

std::size_t MemoryRegion::size() const
{
    return size_;
}

MemoryRegionProtection MemoryRegion::protection() const
{
    return protection_;
}

std::string MemoryRegion::name() const
{
    return name_;
}

bool MemoryRegion::test_protection(MemoryRegionProtection protection) const
{
    return (protection_ & protection) == protection;
}

}
