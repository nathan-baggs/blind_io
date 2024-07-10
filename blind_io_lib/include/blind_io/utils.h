#pragma once

#include <filesystem>
#include <string>

namespace bio
{

/**
 * Helper function to read file.
 *
 * @param path
 *   Path of file to read.
 *
 * @returns
 *   Contents of file as a string.
 */
std::string read_file(const std::filesystem::path &path);

}
