#include "utility.hpp"

bool starts_with(const std::string& str, const char *substr)
{
    return strncmp(str.c_str(), substr, strlen(substr)) == 0;
}


int system(const std::string& command)
{
    return system(command.c_str());
}