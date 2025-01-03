#pragma once

#include <cstdint>

namespace bio
{

/**
 * X64 registers.
 */
struct Registers
{
    std::uintptr_t eax;
    std::uintptr_t ebx;
    std::uintptr_t ecx;
    std::uintptr_t edx;
    std::uintptr_t esi;
    std::uintptr_t edi;
    std::uintptr_t esp;
    std::uintptr_t ebp;
    std::uintptr_t eip;
};

}
