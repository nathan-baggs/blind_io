////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include "memory_region_protection.h"

#include <format>
#include <stdexcept>
#include <string>
#include <string_view>

namespace bio
{

std::string to_string(MemoryRegionProtection protection)
{
    switch (protection)
    {
        using enum MemoryRegionProtection;

        case NO_PROTECTION: return "NO_PROTECTION";
        case READ: return "READ";
        case WRITE: return "WRITE";
        case EXECUTE: return "EXECUTE";
    }

    MemoryRegionProtection protections[] = {
        MemoryRegionProtection::READ, MemoryRegionProtection::WRITE, MemoryRegionProtection::EXECUTE};

    // "strip" off each protection, print and recurse
    for (const auto mask : protections)
    {
        if ((protection & mask) == mask)
        {
            return std::format("{} | {}", to_string(mask), to_string(protection ^ mask));
        }
    }

    throw std::runtime_error(std::format("unknown value ({})", static_cast<std::uint32_t>(protection)));
}

MemoryRegionProtection &operator|=(MemoryRegionProtection &prot1, MemoryRegionProtection prot2)
{
    const auto prot1_int = static_cast<std::underlying_type_t<MemoryRegionProtection>>(prot1);
    const auto prot2_int = static_cast<std::underlying_type_t<MemoryRegionProtection>>(prot2);

    prot1 = static_cast<MemoryRegionProtection>(prot1_int | prot2_int);
    return prot1;
}

MemoryRegionProtection operator|(MemoryRegionProtection prot1, MemoryRegionProtection prot2)
{
    return prot1 |= prot2;
}

MemoryRegionProtection &operator&=(MemoryRegionProtection &prot1, MemoryRegionProtection prot2)
{
    const auto prot1_int = static_cast<std::underlying_type_t<MemoryRegionProtection>>(prot1);
    const auto prot2_int = static_cast<std::underlying_type_t<MemoryRegionProtection>>(prot2);

    prot1 = static_cast<MemoryRegionProtection>(prot1_int & prot2_int);
    return prot1;
}

MemoryRegionProtection operator&(MemoryRegionProtection prot1, MemoryRegionProtection prot2)
{
    return prot1 &= prot2;
}

MemoryRegionProtection &operator^=(MemoryRegionProtection &prot1, MemoryRegionProtection prot2)
{
    const auto prot1_int = static_cast<std::underlying_type_t<MemoryRegionProtection>>(prot1);
    const auto prot2_int = static_cast<std::underlying_type_t<MemoryRegionProtection>>(prot2);

    prot1 = static_cast<MemoryRegionProtection>(prot1_int ^ prot2_int);
    return prot1;
}

MemoryRegionProtection operator^(MemoryRegionProtection prot1, MemoryRegionProtection prot2)
{
    return prot1 ^= prot2;
}

}