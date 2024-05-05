////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "memory_region.h"

namespace bio
{

MemoryRegion::MemoryRegion(std::uintptr_t address, std::size_t size, MemoryRegionProtection protection)
    : address_(address)
    , size_(size)
    , protection_(protection)
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

}