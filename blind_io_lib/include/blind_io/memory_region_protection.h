////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <format>
#include <string>

namespace bio
{

/**
 * Enumeration of possible memory protection properties. Values are set such that these can be combined together using
 * bitwise operations (see overloads).
 */
enum class MemoryRegionProtection
{
    NO_PROTECTION = 0,
    READ = 1 << 0,
    WRITE = 1 << 1,
    EXECUTE = 1 << 2
};

/**
 * Convert a MemoryProtectionRegion to a string representation, handles the case where multiple values have been bitwise
 * or'd together.
 *
 * @param protection
 *   The protection to convert.
 *
 * @returns
 *   String representation of protection.
 */
std::string to_string(MemoryRegionProtection protection);

// overloads of bitwise operators that allows MemoryRegionProtection to be combined like flags

MemoryRegionProtection &operator|=(MemoryRegionProtection &prot1, MemoryRegionProtection prot2);
MemoryRegionProtection operator|(MemoryRegionProtection prot1, MemoryRegionProtection prot2);
MemoryRegionProtection &operator&=(MemoryRegionProtection &prot1, MemoryRegionProtection prot2);
MemoryRegionProtection operator&(MemoryRegionProtection prot1, MemoryRegionProtection prot2);
MemoryRegionProtection &operator^=(MemoryRegionProtection &prot1, MemoryRegionProtection prot2);
MemoryRegionProtection operator^(MemoryRegionProtection prot1, MemoryRegionProtection prot2);

}

/**
 * Specialisation of std::formatter for MemoryRegionProtection.
 */
template <>
struct std::formatter<bio::MemoryRegionProtection>
{
    // simple implementation, we don't need to parse the format string
    constexpr auto parse(std::format_parse_context &ctx)
    {
        return std::begin(ctx);
    }

    // format according to to_string implementation
    auto format(const bio::MemoryRegionProtection &obj, std::format_context &ctx) const
    {
        return std::format_to(ctx.out(), "{}", to_string(obj));
    }
};
