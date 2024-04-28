#include "process_utils.h"

#include <cstdint>
#include <ranges>
#include <stdexcept>
#include <vector>

#include <Windows.h>

#include <Psapi.h>

#include "process.h"

namespace bio
{

std::vector<std::uint32_t> get_pids()
{
    std::vector<DWORD> pids(1024);

    DWORD bytes_returned = 0;

    // the win32 docs state that K32EnumProcesses cannot return the total number of pids available, so we need to keep
    // growing the result buffer until it's not fully filled - at that point we can assume we got all the pids
    do
    {
        pids.resize(pids.size() * 2);

        if (::K32EnumProcesses(pids.data(), static_cast<std::uint32_t>(pids.size() * sizeof(DWORD)), &bytes_returned) ==
            0)
        {
            throw std::runtime_error("failed to get pids");
        }
    } while (bytes_returned == pids.size() * sizeof(DWORD));

    // remove extra entries and convert to standard integral type
    return pids                                                                   //
           | std::views::take(bytes_returned / sizeof(DWORD))                     //
           | std::views::transform([](auto pid) -> std::uint32_t { return pid; }) //
           | std::ranges::to<std::vector>();
}

std::vector<Process> find_process(std::string_view name)
{
    std::vector<Process> procs{};

    for (const auto pid : get_pids())
    {
        try
        {
            Process proc{pid};
            if (proc.name() == name)
            {
                procs.push_back(std::move(proc));
            }
        }
        catch (std::runtime_error &)
        {
        }
    }

    return procs;
}

}