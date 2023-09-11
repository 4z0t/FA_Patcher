
using namespace std;
#include "utility.hpp"
#include <cxxabi.h>
string demangle(const char *symbol)
{
    char* s = abi::__cxa_demangle(symbol, nullptr, nullptr, nullptr);
    string res{s};
    free(s);
    return res;
}

int main()
{
    string name = "s.txt";
    ifstream f(name);
    if (!f.is_open())
        return 1;
    string l;
    while (getline(f, l))
    {
        if (starts_with(l, "_Z"))
        {
            cout << l << " = " << demangle(l.c_str()) << "\n";
        }
    }
    return 0;
}