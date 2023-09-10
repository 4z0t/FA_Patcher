using namespace std;
#include "utility.hpp"

class SymbolInfo
{
public:
    string name;
    size_t position;
};

class ClassInfo : public SymbolInfo
{
};

class NameSpaceInfo : public SymbolInfo
{
};

class FuncInfo : public SymbolInfo
{
public:
    string args;
};

// const regex COMMENT_REGEX(R"((//.*\n)|(/\\*(.*?)\\*/))");
const regex COMMENT_REGEX(R"(//.*\n)");
const regex MULT_SPACES(R"(\s+)");

const regex CLASS_DEF_REGEX(R"((class|struct)\s+([_a-zA-Z]\w*)\s*\{)");
void LookupSymbolInfo(const string &name, vector<SymbolInfo> info)
{

    ifstream f(name);
    if (!f.is_open())
        return;

    string l;
    while (getline(f, l, ';'))
    {

        string res;
        res = regex_replace(l, COMMENT_REGEX, "");
        res = regex_replace(res, MULT_SPACES, " ");

        auto words_begin =
            std::sregex_iterator(res.begin(), res.end(), CLASS_DEF_REGEX);
        auto words_end = std::sregex_iterator();

        for (std::sregex_iterator i = words_begin; i != words_end; ++i)
        {
            smatch match = *i;
            string match_str = match.str();
            cout << "Found " << match_str << '\n';
        }
        // cout << res << "\n";
    }
}

const regex ADDRESS_REGEX(R"(.*?\s([_a-zA-Z]\w*)\([^\(\)]*\)\s*ADDR\((0x[0-9A-Fa-f]{6,8})\)$)");
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
                auto address = address_match[2];
                auto funcname = address_match[1];
                size_t pos;
                int ad = stoi(address, &pos, 16);
                if (addresses.find(ad) != addresses.end())
                {
                    WarnLog("Function '" << funcname << "' has same address as '" << addresses.at(ad) << "' : 0x" << hex << ad << dec);
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

int main()
{
    // unordered_map<int, string> addresses;
    // LookupAddresses("LuaAPI.h", addresses);

    vector<SymbolInfo> info;
    LookupSymbolInfo("LuaAPI.h", info);
}