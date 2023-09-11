
#include "demangler.hpp"
#include <cxxabi.h>
std::string Demangle(const std::string& symbol)
{
    char *s = abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, nullptr);
    std::string res{s};
    free(s);
    return res;
}