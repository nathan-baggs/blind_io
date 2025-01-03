#pragma once

#include <memory>
#include <span>
#include <vector>

#include "instruction.h"

namespace bio
{

class Disassembler
{
  public:
    Disassembler();
    ~Disassembler();

    std::vector<Instruction> disassemble(std::span<const std::uint8_t> data) const;

  private:
    struct implementation;
    std::unique_ptr<implementation> impl_;
};

}
