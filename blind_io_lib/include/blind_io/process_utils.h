////////////////////////////////////////////////////////////////////////////////
//         Distributed under the Boost Software License, Version 1.0.         //
//            (See accompanying file LICENSE or copy at                       //
//                 https://www.boost.org/LICENSE_1_0.txt)                     //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#include "process.h"

// concept to constrain a type to a character type
template <class T>
concept Character =
    std::same_as<T, char> || std::same_as<T, signed char> || std::same_as<T, unsigned char> ||
    std::same_as<T, wchar_t> || std::same_as<T, char8_t> || std::same_as<T, char16_t> || std::same_as<T, char32_t>;

namespace bio
{

/**
 * Get the pids for all currently running processes.
 *
 * @returns
 *   Collection of pids.
 */
std::vector<std::uint32_t> get_pids();

/**
 * Find processes matching a given name
 *
 * @returns
 *   Collection of processes, empty if none were found (or could be opened).
 */
std::vector<Process> find_process(std::string_view name);

/**
 * Replace a given memory pattern with another.
 *
 * @param process
 *   The process to replace memory in.
 *
 * @param region
 *   The region to replace memory in (must be read writable),
 *
 * @param find
 *   The byte pattern to find.
 *
 * @param replace
 *   The byte pattern to replace "find" with (must be the same length as "find").
 *
 * @param num_occurrences
 *   If supplied the maximum number of times to replace "find" (all if not supplied).
 */
void replace_memory(
    const Process &process,
    const MemoryRegion &region,
    std::span<const std::uint8_t> find,
    std::span<const std::uint8_t> replace,
    std::optional<std::size_t> num_occurrences = std::nullopt);

// specialisations of replace_memory for various other types

template <class R>
void replace_memory(
    const Process &process,
    const MemoryRegion &region,
    R &&find,
    R &&replace,
    std::optional<std::size_t> num_occurrences = std::nullopt) requires std::ranges::contiguous_range<R>
{
    const auto find_bytes = reinterpret_cast<const std::uint8_t *>(std::ranges::data(find));
    const auto replace_bytes = reinterpret_cast<const std::uint8_t *>(std::ranges::data(replace));

    replace_memory(
        process,
        region,
        {find_bytes, std::ranges::size(find) * sizeof(std::ranges::range_value_t<R>)},
        {replace_bytes, std::ranges::size(replace) * sizeof(std::ranges::range_value_t<R>)},
        num_occurrences);
}

template <Character T, std::size_t N>
void replace_memory(
    const Process &process,
    const MemoryRegion &region,
    const T (&find)[N],
    const T (&replace)[N],
    std::optional<std::size_t> num_occurrences = std::nullopt)
{
    replace_memory(process, region, std::span{find, N - 1}, std::span{replace, N - 1}, num_occurrences);
}

}
