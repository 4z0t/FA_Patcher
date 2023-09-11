#pragma once
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <io.h>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdio.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define ErrLog(str) \
    cerr << __FUNCTION__ << ":" << __LINE__ << str << "\n"
#define WarnLog(str) \
    cerr << "Warning:\t" << str << "\n"

bool starts_with(std::string str, const char *substr)
{
    return strncmp(str.c_str(), substr, strlen(substr)) == 0;
}
