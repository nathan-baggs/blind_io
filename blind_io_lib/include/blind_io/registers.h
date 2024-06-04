#pragma once

#include <cstdint>

namespace bio
{

/**
 * X64 registers.
 */
struct Registers
{
    std::uintptr_t rax;
    std::uintptr_t rbx;
    std::uintptr_t rcx;
    std::uintptr_t rdx;
    std::uintptr_t rsi;
    std::uintptr_t rdi;
    std::uintptr_t rsp;
    std::uintptr_t rbp;
    std::uintptr_t rip;
    std::uintptr_t r8;
    std::uintptr_t r9;
    std::uintptr_t r10;
    std::uintptr_t r11;
    std::uintptr_t r12;
    std::uintptr_t r13;
    std::uintptr_t r14;
    std::uintptr_t r15;
};

}
