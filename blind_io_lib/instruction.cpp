#include "instruction.h"

#include <cstddef>
#include <string>
#include <string_view>

namespace bio
{

Instruction::Instruction(std::string_view mnemonic, std::string_view operands, std::size_t size)
    : mnemonic_(mnemonic)
    , operands_(operands)
    , size_(size)
{
}

std::string_view Instruction::mnemonic() const
{
    return mnemonic_;
}

std::string_view Instruction::operands() const
{
    return operands_;
}

std::size_t Instruction::size() const
{
    return size_;
}

}
