using namespace std;
#include "FunctionMapper.hpp"
#include "demangler.hpp"
#include "utility.hpp"
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <io.h>
#include <iostream>
#include <regex>
#include <sstream>
#include <stack>
#include <stdio.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

const regex ADDRESS_REGEX(R"(.*?\s(\~?[_a-zA-Z]\w*)\(([^\(\)]*)\)\s*ADDR\((0x[0-9A-Fa-f]{6,8})\)$)");
const regex ARGS_REGEX(R"(\s*(const)?\s*(unsigned)?\s*(([_a-zA-Z]\w*)|(\.{3}))\s*(\*)?\s*([^\,]*)?\s*)");
const regex CLASS_DEF_REGEX(R"((namespace|class|struct)\s+([_a-zA-Z]\w*)\s*\{)");

class SymbolInfo
{
public:
    string name;
    size_t start_position;
    size_t end_position;
    int level;
};

void CountBrackets(
    int &bracket_counter,
    const string &s,
    stack<SymbolInfo> &namespaces)
{
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
                namespaces.pop();
            }
        }
    }
}

string PlusLength(const string &s)
{
    return to_string(s.length()) + s;
}

pair<string, string> MangleName(stack<SymbolInfo> namespaces, const string &funcname)
{
    string name = funcname;
    string mangled_name = PlusLength(funcname);
    bool isFirst = true;
    while (!namespaces.empty())
    {
        const auto &top = namespaces.top();
        if (isFirst)
        {
            if (top.name == funcname)
            {
                mangled_name = "C";
            }
            else if ('~' + top.name == funcname)
            {
                mangled_name = "D";
            }
        }
        mangled_name = PlusLength(top.name) + mangled_name;
        name = top.name + "::" + name;
        namespaces.pop();
        isFirst = false;
    }
    return {mangled_name, name};
}

struct FuncInfo
{
    string mangled_name;
    string name;
    string args;
};

string RecombineArguments(const string &args)
{
    const auto words_begin = std::sregex_iterator(args.begin(), args.end(), ARGS_REGEX);
    const auto words_end = std::sregex_iterator();
    string combined_args = "";
    bool isFirst = true;
    for (std::sregex_iterator i = words_begin; i != words_end; ++i)
    {
        const auto &match = *i;
        const string &_const = match[1];
        const string &_unsigned = match[2];
        const string &_type = match[3];
        const string &_ptr = match[6];
        if (!isFirst)
            combined_args += ", ";
        if (!_unsigned.empty())
            combined_args += _unsigned + ' ';
        combined_args += _type;
        if (!_const.empty() && !_ptr.empty())
            combined_args += ' ' + _const;
        combined_args += _ptr;
        isFirst = false;
    }
    return combined_args;
}

struct LookUpResult
{
    int addr;
    FuncInfo info;
};

LookUpResult MatchFunction(const string &s, unordered_map<int, FuncInfo> &addresses, stack<SymbolInfo> &namespaces)
{
    LookUpResult result = {0, {}};
    smatch address_match;
    if (!regex_match(s, address_match, ADDRESS_REGEX))
    {
        return result;
    }

    if (address_match.size() != 4)
    {
        return result;
    }

    const auto funcname = address_match[1];
    const auto arguments = address_match[2];
    const auto address = address_match[3];

    int ad = stoi(address, nullptr, 16);

    auto [mangled_name, fname] = MangleName(namespaces, funcname);
    auto args = RecombineArguments(arguments);

    result.addr = ad;
    result.info.mangled_name = mangled_name;
    result.info.args = args;
    result.info.name = fname;

    return result;
}

void LookupAddresses(const string &name, unordered_map<int, FuncInfo> &addresses)
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
        const auto words_begin = std::sregex_iterator(res.begin(), res.end(), CLASS_DEF_REGEX);
        const auto words_end = std::sregex_iterator();

        size_t prev_bracket = 0;
        for (std::sregex_iterator i = words_begin; i != words_end; ++i)
        {
            smatch match = *i;
            size_t start_pos = pos + match.position(0);
            size_t end_pos = start_pos + match.length();
            string class_name = match[2];
            size_t end_match = match.position(0) + match.length();
            namespaces.push(SymbolInfo{class_name, start_pos, 0, bracket_counter});
            CountBrackets(bracket_counter, res.substr(prev_bracket, end_match - prev_bracket), namespaces);
            prev_bracket = end_match;
        }
        CountBrackets(bracket_counter, res.substr(prev_bracket), namespaces);

        if (res.size() > 1024)
            continue;

        auto match = MatchFunction(l, addresses, namespaces);
        int addr = match.addr;
        if (addr == 0)
            continue;

        const auto &funcname = match.info.name;
        const auto &arguments = match.info.args;
        const auto &mangled_name = match.info.mangled_name;
        if (addresses.find(addr) != addresses.end())
        {
            WarnLog("Function '" << funcname << "' has same address as '" << addresses.at(addr).name << "' : 0x" << hex << addr << dec);
            return;
        }
        else
        {
            cout << "Registering function '" << funcname << "'"
                 << "(" << arguments << ") at 0x" << hex << addr << dec << "\t" << mangled_name
                 << "\n";
            addresses[addr] = {mangled_name, funcname, arguments};
        }
    }

    if (bracket_counter != 0)
    {
        WarnLog("Unbalanced brackets in " << name << " detected! " << bracket_counter);
    }
}

struct Similarity
{
    int addr;
    int similarity;
};

struct MangledFunc : FuncInfo
{
    int similarity;
};

Similarity FindName(const string &mangled_name, const unordered_map<int, FuncInfo> &addresses)
{
    Similarity result = {0, 0};
    for (const auto &[addr, funcinfo] : addresses)
    {
        const auto mangled = funcinfo.mangled_name;
        const auto funcname = funcinfo.name;
        auto args = funcinfo.args;
        string::size_type pos = mangled_name.find(mangled);
        int similarity = 0;

        if (pos != string::npos)
        {
            similarity++;
            string demangled_name = Demangle(mangled_name);
            pos = demangled_name.find(funcname);

            if (pos != string::npos)
            {
                similarity++;
                if (args.empty())
                    args = "()";
                pos = demangled_name.find(args);
                if (pos != string::npos)
                {
                    similarity += args.length();
                }
            }
        }
        if (similarity > result.similarity)
            result = {addr, similarity};
    }
    return result;
}

void MapNames(const string &output_dir, const string &target_dir, const string &file_name, unordered_map<int, MangledFunc> &mangled_addresses, const unordered_map<int, FuncInfo> &addresses)
{
    const string file_path = target_dir + file_name;
    if (system("g++ -D__GETADDR -c -m32 -fpermissive -std=c++17 -Wno-return-type " + file_path + " -o " + output_dir + file_name + ".gch"))
    {
        ErrLog("unable to compile header file " << file_path);
        return;
    }

    if (system("strings " + output_dir + file_name + ".gch >> " + output_dir + "symbols.txt"))
    {
        ErrLog("unable to extract symbols " << file_name);
        return;
    }

    ifstream strings_file(output_dir + "symbols.txt");
    if (!strings_file.is_open())
    {
        ErrLog("unable to open symbols file");
        return;
    }
    string line;
    while (getline(strings_file, line))
    {
        if (!starts_with(line, "_Z"))
            continue;

        auto [addr, similarity] = FindName(line, addresses);
        if (addr == 0)
            continue;

        if (mangled_addresses.find(addr) != mangled_addresses.end())
        {
            const auto &m = mangled_addresses.at(addr);
            if (m.mangled_name != line)
            {
                if (m.similarity < similarity)
                {
                    const auto &info = addresses.at(addr);
                    cout << "Found better mangled version of function '" << info.name << "(" << info.args << ")' is '" << line << "' at 0x" << hex << addr << dec << '\n';
                    mangled_addresses[addr] = {line, info.name, info.args, similarity};
                }
            }
        }
        else
        {
            const auto &info = addresses.at(addr);
            cout << "Found mangled version of function '" << info.name << '(' << info.args << ")' is '" << line << "' at 0x" << hex << addr << dec << '\n';
            mangled_addresses[addr] = {line, info.name, info.args, similarity};
        }
    }
}

unordered_map<int, MangledFunc> MapMangledNames(const string &output_dir, const string &target_dir, const string &mask, const unordered_map<int, FuncInfo> &addresses)
{
    unordered_map<int, MangledFunc> mangled_addresses{};
    _finddata_t data;
    int hf = _findfirst((target_dir + mask).c_str(), &data);
    if (hf < 0)
        return mangled_addresses;
    do
    {
        MapNames(output_dir, target_dir, data.name, mangled_addresses, addresses);
    } while (_findnext(hf, &data) != -1);
    _findclose(hf);

    return mangled_addresses;
}

unordered_map<int, FuncInfo> ExtractFunctionAddresses(const string &dir, const string &mask)
{
    unordered_map<int, FuncInfo> addresses{};
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
#define COMMENT(s) "/* " << s << " */"
void CreateSectionWithAddresses(const string &file_name, const unordered_map<int, MangledFunc> &addresses)
{
    ofstream new_file(file_name);
    if (!new_file.is_open())
    {
        ErrLog("Couldn't open new section file " << file_name);
        return;
    }
    for (const auto &[addr, mangled_func] : addresses)
    {
        const auto &funcname = mangled_func.name;
        const auto &mangled_name = mangled_func.mangled_name;
        new_file << "_" << mangled_name << " = 0x" << hex << addr << ";    " << COMMENT(funcname << "(" << mangled_func.args << ")") << "\n";
    }
    new_file.close();
}

int main(int argc, char **argv)
{
    if (argc != 6)
    {
        ErrLog("Incorrect argument count expected 6, but got " << argc);
        return 1;
    }
    // target_file scandir file_format output_dir output_file
    const string target_file = argv[1];
    const string target_dir = argv[2];
    const string scan_format = argv[3];
    const string output_dir = argv[4];
    const string output_file = argv[5];
    auto addresses = ExtractFunctionAddresses(target_dir, scan_format);
    auto mangled_addresses = MapMangledNames(output_dir, target_dir, target_file, addresses);
    CreateSectionWithAddresses(output_dir + output_file, mangled_addresses);
    return 0;
}