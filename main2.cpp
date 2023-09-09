using namespace std;

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <io.h>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdio.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

const regex ADDRESS_REGEX(R"(.*ADDR\((0x[0-9A-Fa-f]{6,8})\).*\s([_a-zA-Z]\w*)\(.*\))");
void LookupAddresses(const string &name, unordered_map<int, string> &addresses)
{
    ifstream f(name);
    if (!f.is_open())
        return;

    string l;
    while (getline(f, l, ';'))
    {
        if (l.size() > 1024)
            continue;

        smatch address_match;
        replace(l.begin(), l.end(), '\n', ' ');
        if (regex_match(l, address_match, ADDRESS_REGEX))
        {
            if (address_match.size() == 3)
            {
                auto address = address_match[1];
                auto funcname = address_match[2];
                size_t pos;
                int ad = stoi(address, &pos, 16);
                if (addresses.find(ad) != addresses.end())
                {
                    cerr << "Function '" << funcname << "' has same address as '" << addresses.at(ad) << "' : 0x" << hex << ad << dec << '\n';
                    return;
                }
                else
                {
                    cout << "Registering function '" << funcname << "' at 0x" << hex << ad << dec << '\n';
                    addresses[ad] = funcname;
                }
            }
        }
    }
}

unordered_map<int, string> ExtractFunctionAddresses(const string &dir, const char *mask)
{
    unordered_map<int, string> addresses{};
    _finddata_t data;
    int hf = _findfirst((dir + mask).c_str(), &data);
    if (hf < 0)
        return addresses;
    do
    {
        LookupAddresses(dir + data.name, addresses);
    } while (_findnext(hf, &data) != -1);
    _findclose(hf);

    return addresses;
}

int main()
{
    ExtractFunctionAddresses("./section/include/", "*.h");

    return 0;
}