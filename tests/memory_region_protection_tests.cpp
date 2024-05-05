////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#include <type_traits>

#include <gtest/gtest.h>

#include "memory_region_protection.h"

TEST(memory_region_protection, or_operator)
{
    const auto prot = bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE;

    ASSERT_EQ(static_cast<std::underlying_type_t<bio::MemoryRegionProtection>>(prot), 5);
}

TEST(memory_region_protection, or_assign_operator)
{
    auto prot = bio::MemoryRegionProtection::READ;
    prot |= bio::MemoryRegionProtection::WRITE;

    ASSERT_EQ(static_cast<std::underlying_type_t<bio::MemoryRegionProtection>>(prot), 3);
}

TEST(memory_region_protection, and_operator)
{
    ASSERT_EQ(
        (bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE) &
            bio::MemoryRegionProtection::EXECUTE,
        bio::MemoryRegionProtection::EXECUTE);
}

TEST(memory_region_protection, xor_operator)
{
    const auto prot = bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE;

    ASSERT_EQ(prot ^ bio::MemoryRegionProtection::READ, bio::MemoryRegionProtection::EXECUTE);
}

TEST(memory_region_protection, xor_assign_operator)
{
    auto prot = bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE;
    prot ^= bio::MemoryRegionProtection::EXECUTE;

    ASSERT_EQ(prot, bio::MemoryRegionProtection::READ);
}

TEST(memory_region_protection, to_string)
{
    ASSERT_EQ(bio::to_string(bio::MemoryRegionProtection::READ), "READ");
    ASSERT_EQ(bio::to_string(bio::MemoryRegionProtection::WRITE), "WRITE");
    ASSERT_EQ(bio::to_string(bio::MemoryRegionProtection::EXECUTE), "EXECUTE");

    ASSERT_EQ(bio::to_string(bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE), "READ | WRITE");
    ASSERT_EQ(
        bio::to_string(bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE), "READ | EXECUTE");
    ASSERT_EQ(
        bio::to_string(bio::MemoryRegionProtection::WRITE | bio::MemoryRegionProtection::EXECUTE), "WRITE | EXECUTE");
    ASSERT_EQ(
        bio::to_string(
            bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE |
            bio::MemoryRegionProtection::EXECUTE),
        "READ | WRITE | EXECUTE");
}

TEST(memory_region_protection, format)
{
    ASSERT_EQ(std::format("{}", bio::MemoryRegionProtection::READ), "READ");
    ASSERT_EQ(std::format("{}", bio::MemoryRegionProtection::WRITE), "WRITE");
    ASSERT_EQ(std::format("{}", bio::MemoryRegionProtection::EXECUTE), "EXECUTE");

    ASSERT_EQ(
        std::format("{}", bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE), "READ | WRITE");
    ASSERT_EQ(
        std::format("{}", bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::EXECUTE), "READ | EXECUTE");
    ASSERT_EQ(
        std::format("{}", bio::MemoryRegionProtection::WRITE | bio::MemoryRegionProtection::EXECUTE),
        "WRITE | EXECUTE");
    ASSERT_EQ(
        std::format(
            "{}",
            bio::MemoryRegionProtection::READ | bio::MemoryRegionProtection::WRITE |
                bio::MemoryRegionProtection::EXECUTE),
        "READ | WRITE | EXECUTE");
}