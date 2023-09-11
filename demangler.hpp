#pragma once
#include "utility.hpp"
#include <cxxabi.h>
string demangle(std::string symbol)
{
    char* s = abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, nullptr);
    string res{s};
    free(s);
    return res;
}



