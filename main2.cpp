using namespace std;
#include "utility.hpp"
#include <stack>

class SymbolInfo
{
public:
    string name;
    size_t start_position;
    size_t end_position;
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

const regex CLASS_DEF_REGEX(R"((namespace|class|struct)\s+([_a-zA-Z]\w*)\s*\{)");

int CountBrackets(const string &s, size_t start_pos, size_t end_pos)
{
    int i = 0;
    for (size_t j = start_pos; j < end_pos; j++)
    {
        char c = s[j];
        if (c == '{')
        {
            i++;
        }
        else if (c == '}')
        {
            i--;
        }
    }
    return i;
}

void LookupSymbolInfo(const string &name, vector<SymbolInfo> info)
{

    ifstream f(name);
    if (!f.is_open())
        return;

    stack<SymbolInfo> namespaces{};
    int bracket_counter = 0;

    string l;

    for (size_t pos = 0; getline(f, l, ';'); pos = f.tellg())
    {
        replace(l.begin(), l.end(), '\n', ' ');
        string res = l;
        // res = regex_replace(l, COMMENT_REGEX, "");
        // res = regex_replace(res, MULT_SPACES, " ");
        const auto words_begin = std::sregex_iterator(res.begin(), res.end(), CLASS_DEF_REGEX);
        const auto words_end = std::sregex_iterator();

        size_t prev_bracket = 0;
        for (std::sregex_iterator i = words_begin; i != words_end; ++i)
        {
            smatch match = *i;
            size_t start_pos = pos + match.position(0);
            size_t end_pos = start_pos + match.length();
            string class_name = match[2];
            cout << start_pos << "\n";
            cout << end_pos << "\n";
            cout << class_name << "\n";

            namespaces.push(SymbolInfo{class_name, start_pos, 0});

            bracket_counter += CountBrackets(res, prev_bracket, match.position(0));
            prev_bracket = match.position(0);
        }
        bracket_counter += CountBrackets(res, prev_bracket, res.size());
    }
    cout << bracket_counter << "\n";
}

const regex ADDRESS_REGEX(R"(.*?\s([_a-zA-Z]\w*)\(([^\(\)]*)\)\s*ADDR\((0x[0-9A-Fa-f]{6,8})\)$)");
void LookupAddresses(const string &name, unordered_map<int, string> &addresses)
{
    ifstream f(name);
    if (!f.is_open())
        return;

    string l;
    for (size_t file_pos = 0; getline(f, l, ';'); file_pos = f.tellg())
    {
        if (l.size() > 1024)
            continue;

        smatch address_match;
        replace(l.begin(), l.end(), '\n', ' ');
        if (regex_match(l, address_match, ADDRESS_REGEX))
        {
            if (address_match.size() == 4)
            {
                const auto funcname = address_match[1];
                const auto arguments = address_match[2];
                const auto address = address_match[3];

                int ad = stoi(address, nullptr, 16);
                if (addresses.find(ad) != addresses.end())
                {
                    WarnLog("Function '" << funcname << "' has same address as '" << addresses.at(ad) << "' : 0x" << hex << ad << dec);
                    return;
                }
                else
                {
                    cout << address_match.position(1) + file_pos << "\n";
                    cout << "Registering function '" << funcname << "'"
                         << "(" << arguments << ") at 0x" << hex << ad << dec << '\n';
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