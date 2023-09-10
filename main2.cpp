using namespace std;
#include "utility.hpp"
#include <stack>

class SymbolInfo
{
public:
    string name;
    size_t start_position;
    size_t end_position;
    int level;
};

class ClassInfo : public SymbolInfo
{
};

class NameSpaceInfo : public SymbolInfo
{
};

class FuncInfo
{
public:
    string name;
    vector<string> args;
};

// const regex COMMENT_REGEX(R"((//.*\n)|(/\\*(.*?)\\*/))");
const regex COMMENT_REGEX(R"(//.*\n)");
const regex MULT_SPACES(R"(\s+)");

const regex CLASS_DEF_REGEX(R"((namespace|class|struct)\s+([_a-zA-Z]\w*)\s*\{)");
const regex ADDRESS_REGEX(R"(.*?\s([_a-zA-Z]\w*)\(([^\(\)]*)\)\s*ADDR\((0x[0-9A-Fa-f]{6,8})\)$)");
void CountBrackets(
    int &bracket_counter,
    const string &s,
    stack<SymbolInfo> &namespaces,
    size_t pos)
{
    size_t j = 0;
    for (char c : s)
    {
        if (c == '{')
        {
            ++bracket_counter;
            continue;
        }
        if (c == '}')
        {
            --bracket_counter;
            if (!namespaces.empty() && namespaces.top().level == bracket_counter)
            {
                auto ns = namespaces.top();
                namespaces.pop();
                ns.end_position = pos + j;
            }
        }

        j++;
    }
}

string PlusLength(const string &s)
{
    return to_string(s.length()) + s;
}

string MangleName(stack<SymbolInfo> namespaces, const string &funcname)
{
    string res = PlusLength(funcname);
    while (!namespaces.empty())
    {
        res = PlusLength(namespaces.top().name) + res;
        namespaces.pop();
    }
    return res;
}

const unordered_map<string, string> TYPE_MAP{
    {"usignedint", "j"},
    {"char", "c"},
    {"float", "f"},
    {"int", "i"},
};

string MangleType(const string &_const, const string &_type, const string &_ptr)
{
    string name = "";
    if (!_ptr.empty())
    {
        name = "P" + name;
        if (!_const.empty())
        {
            name += "K";
        }
    }
    if (TYPE_MAP.find(_type) == TYPE_MAP.end())
    {
        name += PlusLength(_type);
    }
    else
    {
        name += TYPE_MAP.at(_type);
    }
    return name;
}

string MangleArgs(vector<string> &args)
{
    string name = "";

    return name;
}

const regex ARGS_REGEX(R"(\s*(const)?\s*(unsigned)?\s*([_a-zA-Z]\w*)\s*(\*)?\s*([^\,]*)?\s*)");
vector<string> MangleArguments(string args)
{
    cout << args << "\n\n";
    const auto words_begin = std::sregex_iterator(args.begin(), args.end(), ARGS_REGEX);
    const auto words_end = std::sregex_iterator();

    vector<string> mangled_args{};
    for (std::sregex_iterator i = words_begin; i != words_end; ++i)
    {
        smatch match = *i;

        mangled_args.push_back(MangleType(match[1], match[2].str() + match[3].str(), match[4]));
    }
    cout << '\n';
    return mangled_args;
}

void LookupSymbolInfo(const string &name, unordered_map<int, FuncInfo> &addresses)
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
            // cout << start_pos << "\n";
            // cout << end_pos << "\n";
            // cout << class_name << "\n";
            size_t end_match = match.position(0) + match.length();
            namespaces.push(SymbolInfo{class_name, start_pos, 0, bracket_counter});
            cout << match[0] << " " << end_match << " " << bracket_counter << "\n";
            CountBrackets(bracket_counter, res.substr(prev_bracket, end_match - prev_bracket), namespaces, pos);
            prev_bracket = end_match;
        }
        CountBrackets(bracket_counter, res.substr(prev_bracket), namespaces, pos);

        if (res.size() > 1024)
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
                    WarnLog("Function '" << funcname << "' has same address as '" << addresses.at(ad).name << "' : 0x" << hex << ad << dec);
                    return;
                }
                else
                {
                    string fname = MangleName(namespaces, funcname);
                    cout << address_match.position(1) + pos << "\n";
                    auto args = MangleArguments(arguments);
                    cout << "Registering function '" << fname << "'"
                         << "(" << arguments << ") at 0x" << hex << ad << dec << '\n';
                    addresses[ad] = {fname, args};
                }
            }
        }
    }
}

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
    // LookupAddresses("LuaAPI.h", addresses);

    unordered_map<int, FuncInfo> addresses;
    LookupSymbolInfo("LuaAPI.h", addresses);
}