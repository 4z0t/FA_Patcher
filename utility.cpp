#include "utility.hpp"

bool starts_with(std::string str, const char *substr)
{
    return strncmp(str.c_str(), substr, strlen(substr)) == 0;
}