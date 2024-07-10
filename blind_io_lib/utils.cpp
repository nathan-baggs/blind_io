#include "utils.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace bio
{

std::string read_file(const std::filesystem::path &path)
{
    const std::ifstream file{path};
    if (!file)
    {
        throw std::runtime_error("failed to read file");
    }

    std::stringstream strm{};
    strm << file.rdbuf();

    return strm.str();
}

}
