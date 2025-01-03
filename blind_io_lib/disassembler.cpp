#include "disassembler.h"

#include <memory>
#include <stdexcept>

#include <capstone/capstone.h>

namespace
{

struct CapstoneDisasembler
{
    CapstoneDisasembler(::csh handle, std::span<const std::uint8_t> data)
    {
        count = ::cs_disasm(handle, data.data(), data.size(), 0, 0, &instruction);
        if (count == 0)
        {
            throw std::runtime_error("failed to disassemble data");
        }
    }

    ~CapstoneDisasembler()
    {
        ::cs_free(instruction, count);
    }

    ::cs_insn *instruction;
    std::size_t count;
};

}

namespace bio
{

struct Disassembler::implementation
{
    ::csh handle;
};

Disassembler::Disassembler()
    : impl_(std::make_unique<implementation>())
{
    if (::cs_open(CS_ARCH_X86, CS_MODE_32, &impl_->handle) != CS_ERR_OK)
    {
        throw std::runtime_error("failed to initialise capstone");
    }

    if (::cs_option(impl_->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
    {
        throw std::runtime_error("failed to set capstone option");
    }
}

Disassembler::~Disassembler()
{
    ::cs_close(&impl_->handle);
}

std::vector<Instruction> Disassembler::disassemble(std::span<const std::uint8_t> data) const
{
    std::vector<Instruction> instructions{};

    CapstoneDisasembler disassembler{impl_->handle, data};

    for (auto i = 0u; i < disassembler.count; ++i)
    {
        const auto &instruction = disassembler.instruction[i];
        instructions.emplace_back(instruction.mnemonic, instruction.op_str, instruction.size);
    }

    return instructions;
}
}
