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

void MapNames(const string &dir, const string &file_name, unordered_map<int, MangledFunc> &mangled_addresses, const unordered_map<int, FuncInfo> &addresses)
{
    const string file_path = dir + file_name;
    if (system("g++ -D__GETADDR -c -m32 -fpermissive -std=c++17 -Wno-return-type " + file_path + " -o ./build/" + file_name + ".gch"))
    {
        ErrLog("unable to compile header file " << file_path);
        return;
    }

    if (system("strings ./build/" + file_name + ".gch >> ./build/symbols.txt"))
    {
        ErrLog("unable to extract symbols " << file_name);
        return;
    }

    ifstream strings_file("./build/symbols.txt");
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
                    cout << "Found better mangled version of function '" << addresses.at(addr).name << "' is '" << line << "' at 0x" << hex << addr << dec << '\n';
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

unordered_map<int, MangledFunc> MapMangledNames(const string &dir, const char *mask, const unordered_map<int, FuncInfo> &addresses)
{
    unordered_map<int, MangledFunc> mangled_addresses{};
    _finddata_t data;
    int hf = _findfirst((dir + mask).c_str(), &data);
    if (hf < 0)
        return mangled_addresses;
    do
    {
        MapNames(dir, data.name, mangled_addresses, addresses);
    } while (_findnext(hf, &data) != -1);
    _findclose(hf);

    return mangled_addresses;
}

unordered_map<int, FuncInfo> ExtractFunctionAddresses(const string &dir, const char *mask)
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

void RemoveFiles(const string &dir, const char *mask)
{
    _finddata_t data;
    int hf = _findfirst((dir + mask).c_str(), &data);
    if (hf < 0)
        return;
    do
    {
        remove((dir + data.name).c_str());
    } while (_findnext(hf, &data) != -1);
    _findclose(hf);
}

void ParseMap(const char *mapfile, const char *outfile)
{
    ifstream ifile(mapfile);
    ofstream ofile(outfile);
    ofile << "#define QUAUX(X) #X\n#define QU(X) QUAUX(X)\n\n";
    string l;
    bool need = false;
    while (getline(ifile, l))
    {
        if (starts_with(l, " .text.startup "))
            ofile << "#define STARTUP " << l.substr(16, 10) << "\n";
        else if (starts_with(l, " .text ") ||
                 starts_with(l, " .data ") ||
                 starts_with(l, " .bss "))
        {
            need = true;
            continue;
        }
        if (need && starts_with(l, "  "))
        {
            int i = l.find("(");
            if (i > 0)
                l.resize(i);
            stringstream ss(l);
            string w, w2;
            ss >> w;
            ss >> w2;
            ofile << "#define " << w2 << " " << w << "\n";
            continue;
        }
        need = false;
    }
    ofile.close();
}

struct PESect
{
    char name[8];
    int32_t VSize, VOffset, FSize, FOffset;
    char pad[12];
    uint32_t Flags;
};

class PEFile : public fstream
{
public:
    uint32_t offset, imgbase, sectalign, filealign;
    vector<PESect> sects;

    PEFile(string filename);
    PESect *FindSect(const char *name);
    void Save();
};

PEFile::PEFile(string filename) : fstream(filename, binary | in | out)
{
    if (!is_open())
    {
        ErrLog(" -> Failed to open " << filename);
        return;
    }
    seekp(0x3c);
    read((char *)&offset, sizeof(offset));
    uint16_t scnt;
    seekp(offset + 0x6);
    read((char *)&scnt, sizeof(scnt));
    sects.resize(scnt);
    seekp(offset + 0x34);
    read((char *)&imgbase, sizeof(imgbase) * 3);
    seekp(offset + 0xf8);
    read((char *)sects.data(), sizeof(PESect) * scnt);
}

PESect *PEFile::FindSect(const char *name)
{
    for (int i = 0; i < sects.size(); i++)
        if (strcmp(name, (const char *)&sects[i].name) == 0)
            return &sects[i];
    return NULL;
}

void PEFile::Save()
{
    uint16_t scnt = sects.size();
    seekp(offset + 0x6);
    write((char *)&scnt, sizeof(scnt));
    uint32_t imgsize = sects.back().VOffset + sects.back().VSize;
    seekp(offset + 0x50);
    write((char *)&imgsize, sizeof(imgsize));
    seekp(offset + 0xf8);
    write((char *)sects.data(), sizeof(PESect) * scnt);
}

struct COFFSect
{
    char name[8];
    uint32_t size, offset;
};

class COFFFile
{
public:
    string name;
    vector<COFFSect> sects;

    COFFFile(string filename);
    COFFSect *FindSect(const char *name);
};

COFFFile::COFFFile(string filename)
{
    fstream f(filename, ios::binary | ios::in | ios::out);
    if (!f.is_open())
    {
        ErrLog(" -> Failed to open " << filename);
        return;
    }
    name = filename;
    f.seekg(8);
    uint32_t pos, cnt;
    f.read((char *)&pos, sizeof(pos));
    f.read((char *)&cnt, sizeof(cnt));
    f.seekg(pos);
    for (int i = 0; i < cnt; i++)
    {
        char data[18];
        f.read(data, sizeof(data));
        if (data[0] != 'h')
        {
            f.seekg(sizeof(data) * data[17], ios_base::cur);
            i += data[17];
            continue;
        }
        COFFSect *sect = FindSect(data);
        if (!sect)
        {
            sects.push_back({0, 0, 0});
            sect = &sects.back();
            strncpy(sect->name, data, sizeof(sect->name));
        }
        if (data[17] > 0)
        {
            f.read(data, sizeof(data));
            sect->size = *(uint32_t *)&data[0];
            i++;
            continue;
        }
        sect->offset = *(uint32_t *)&data[8];
    }
    f.seekg(2);
    uint16_t scnt;
    f.read((char *)&scnt, sizeof(scnt));
    f.seekg(20);
    for (int i = 0; i < scnt; i++)
    {
        char data[8];
        f.read(data, sizeof(data));
        if (data[0] != 'h')
        {
            f.seekg(0x20, ios_base::cur);
            continue;
        }
        COFFSect *sect = FindSect(data);
        if (sect)
        {
            f.seekp(f.tellg() + 8LL);
            f.write((char *)&sect->size, sizeof(sect->size));
            continue;
        }
        f.seekg(0x20, ios_base::cur);
    }
    f.close();
}

COFFSect *COFFFile::FindSect(const char *name)
{
    for (int i = 0; i < sects.size(); i++)
        if (strcmp(name, (const char *)&sects[i].name) == 0)
            return &sects[i];
    return NULL;
}

void MakeLists(const string &dir, const char *mask, ofstream &ret)
{
    string path = dir + mask;
    _finddata_t fdata;
    int hf = _findfirst(path.c_str(), &fdata);
    if (hf < 0)
    {
        ErrLog(" -> No files matching the pattern: " << path);
        return;
    }
    regex pattern(R"(PatcherList_([a-zA-Z][a-zA-Z0-9]*)_?([a-zA-Z_]\w*)?)");
    unordered_map<string, unordered_set<string>> lists;
    do
    {
        path = dir + fdata.name;
        ifstream src(path.c_str());
        if (!src.is_open())
        {
            ErrLog(" -> Failed to open " << path);
            continue;
        }
        string l;
        smatch match;
        while (getline(src, l))
            if (regex_search(l, match, pattern))
                if (match[2] == "")
                    lists[match[1]];
                else
                    lists[match[1]].insert(match[2]);
        src.close();
    } while (_findnext(hf, &fdata) != -1);
    _findclose(hf);
    for (const auto &[listName, elems] : lists)
    {
        ret << "void* " << listName << "[] = {";
        for (const auto &elem : elems)
            ret << "&" << elem << ", ";
        ret << "0};\n";
    }
}

void SigApply(vector<uint8_t> &data, string sig, string patch)
{
    auto strToBytes = [](string &str, vector<uint8_t> &bytes, vector<bool> &mask)
    {
        str.erase(remove(str.begin(), str.end(), ' '), str.end());
        for (size_t i = 0; i < str.length(); i += 2)
        {
            string byteStr = str.substr(i, 2);
            if (byteStr != "??")
            {
                uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
                bytes.push_back(byte);
                mask.push_back(true);
            }
            else
            {
                bytes.push_back(0);
                mask.push_back(false);
            }
        }
    };
    vector<uint8_t> sigBytes, patchBytes;
    vector<bool> sigMask, patchMask;

    strToBytes(sig, sigBytes, sigMask);
    strToBytes(patch, patchBytes, patchMask);
    auto sigSize = sigBytes.size();
    auto patchSize = patchBytes.size();
    if (sigSize < patchSize)
        ErrLog(" -> Patch must be no larger than signature");

    size_t patched = 0;
    for (size_t i = 0; i <= data.size() - sigSize; i++)
    {
        bool sigFound = true;
        for (size_t j = 0; j < sigSize; j++)
            if (sigMask[j])
                if (data[i + j] != sigBytes[j])
                {
                    sigFound = false;
                    break;
                }
        if (!sigFound)
            continue;
        for (size_t j = 0; j < patchSize; j++)
            if (patchMask[j])
                data[i + j] = patchBytes[j];
        i += sigSize - 1;
        patched++;
    }
    cout << "Signature: " << sig << "\tPatched: " << patched << " times"
         << "\n";
}

string oldfile("ForgedAlliance_base.exe");
string newfile("ForgedAlliance_exxt.exe");
string newsect(".exxt");
uint32_t sectsize = 0x80000;
string cflags("-pipe -m32 -Os -nostartfiles -w -fpermissive -masm=intel -std=c++17 -march=core2 -mfpmath=both");
bool use_address_mapping = false;

#define align(v, a) ((v) + ((a)-1)) & ~((a)-1)

void LoadConfig(const string &file_name)
{
    ifstream f(file_name);
    if (f.is_open())
    {
        string l;
        while (getline(f, l))
        {
            stringstream ss(l);
            ss >> l;
            if (l == "oldfile")
                ss >> oldfile;
            else if (l == "newfile")
                ss >> newfile;
            else if (l == "newsect")
                ss >> newsect;
            else if (l == "sectsize")
                ss >> hex >> sectsize;
            else if (l == "cflags")
                getline(ss, cflags);
            else if (l == "addressmapping")
                ss >> use_address_mapping;
        }
    }
    else
    {
        ofstream f(file_name);
        f << "oldfile " << oldfile << "\n";
        f << "newfile " << newfile << "\n";
        f << "newsect " << newsect << "\n";
        f << "sectsize 0x" << hex << sectsize << "\n";
        f << "cflags " << cflags << "\n";
        f << "addressmapping " << use_address_mapping << "\n";
    }
}

int main(int argc, char **argv)
{
    if (system("g++ --version"))
        return 1;

    string config_name = "config.txt";
    if (argc == 2)
    {
        config_name = argv[1];
    }
    LoadConfig(config_name);

    ifstream src(oldfile, ios::binary);
    if (!src.is_open())
    {
        ErrLog(" -> Failed to open " << oldfile);
        return 1;
    }
    ofstream dst(newfile, ios::binary);
    if (!dst.is_open())
    {
        ErrLog(" -> Failed to create " << newfile);
        return 1;
    }
    dst << src.rdbuf();
    dst.close();
    src.close();

    RemoveFiles("./build/", "!symbols.ld");
    filesystem::create_directory("build");

    PEFile nf(newfile);
    if (nf.FindSect(newsect.c_str()))
    {
        ErrLog(" -> Section already exists: " << newsect);
        return 1;
    }
    int newVOffset = 0, newFOffset = 0;
    for (int i = 0; i < nf.sects.size(); i++)
    {
        PESect *sect = &nf.sects[i];
        uint32_t lastOffset;
        lastOffset = sect->VOffset + sect->VSize;
        if (lastOffset > newVOffset)
            newVOffset = lastOffset;
        lastOffset = sect->FOffset + sect->FSize;
        if (lastOffset > newFOffset)
            newFOffset = lastOffset;
    }
    newVOffset = align(newVOffset, nf.sectalign);
    newFOffset = align(newFOffset, nf.filealign);

    ofstream smain("section.cpp");
    _finddata_t fdata;
    int hf = _findfirst("./section/*.cpp", &fdata);
    do
    {
        smain << "#include \"section/" << fdata.name << "\"\n";
    } while (_findnext(hf, &fdata) != -1);
    _findclose(hf);
    MakeLists("./section/", "*.cpp", smain);
    smain.close();

    if (use_address_mapping)
    {
        auto addresses = ExtractFunctionAddresses("./section/include/", "*.h");
        auto mangled_addresses = MapMangledNames("./section/include/", "funcmap.h", addresses);
        CreateSectionWithAddresses("./build/symbols.ld", mangled_addresses);
    }

    if (system("cd build && g++ " + cflags +
               " -Wl,-T,../section.ld,--image-base," +
               to_string(nf.imgbase + newVOffset - 0x1000) +
               ",-s,-Map,sectmap.txt ../section.cpp"))
        return 1;

    ParseMap("build/sectmap.txt", "define.h");

    RemoveFiles("./build/", "*.o");
    RemoveFiles("./build/", "*.gch");

    if (system("cd build && g++ -c " + cflags + " ../hooks/*.cpp"))
        return 1;

    ofstream pld("patch.ld");
    pld << "OUTPUT_FORMAT(pei-i386)\n"
           "OUTPUT(build/patch.pe)\n"
           "SECTIONS {\n";

    vector<COFFFile> hooks;
    hf = _findfirst("./build/*.o", &fdata);
    do
    {
        hooks.push_back(COFFFile(string("build/") + fdata.name));
    } while (_findnext(hf, &fdata) != -1);
    _findclose(hf);

    int hi = 0;
    for (int i = 0; i < hooks.size(); i++)
    {
        COFFFile *hf = &hooks[i];
        for (int j = 0; j < hf->sects.size(); j++)
        {
            COFFSect *sect = &hf->sects[j];
            pld << "  .h" << to_string(hi++) << " 0x" << hex << sect->offset;
            pld << " : SUBALIGN(1) {\n    " << hf->name << "(" << sect->name << ")\n  }\n";
        }
    }

    pld << "  " << newsect << " 0x" << hex << nf.imgbase + newVOffset << ": {\n\
    build/section.pe\n    *(.data)\n    *(.bss)\n    *(.rdata)\n  }\n";
    pld << "  /DISCARD/ : {\n    *(.text)\n    *(.text.startup)\n\
    *(.rdata$zzz)\n    *(.eh_frame)\n    *(.ctors)\n    *(.reloc)\n  }\n}";
    pld.close();

    if (system("ld -T patch.ld --image-base " +
               to_string(nf.imgbase) +
               " -s -Map build/patchmap.txt"))
        return 1;

    PEFile pf("build/patch.pe");
    hi = 0;
    for (int i = 0; i < hooks.size(); i++)
    {
        COFFFile *hf = &hooks[i];
        if (hf->sects.empty())
            cout << "No hooks in " << hf->name << '\n';
        for (int j = 0; j < hf->sects.size(); j++)
        {
            PESect *psect = pf.FindSect((".h" + to_string(hi)).c_str());
            if (psect->VOffset < 0)
            {
                cout << "Hook invalid offset " << hf->name << " .h" << j << "\n";
                continue;
            }
            uint32_t size = hf->sects[j].size;
            char *buf = new char[size]{};
            pf.seekp(psect->FOffset);
            pf.read(buf, size);
            nf.seekp(psect->VOffset);
            nf.write(buf, size);
            delete[] buf;
            hi++;
        }
    }

    PESect *sect = pf.FindSect(newsect.c_str());
    nf.sects.push_back(*sect);
    PESect *nsect = &nf.sects.back();
    nsect->VOffset = newVOffset;
    nsect->FOffset = newFOffset;
    if (sectsize > 0)
    {
        if (sectsize < sect->FSize)
        {
            ErrLog(" -> Section size too small. Required: 0x" << hex << sect->FSize);
            return 1;
        }
        sect->VSize = sectsize;
        sect->FSize = sectsize;
    }
    char *buf = new char[sect->FSize]{};
    pf.seekp(sect->FOffset);
    pf.read(buf, sect->FSize);
    nf.seekp(nsect->FOffset);
    nf.write(buf, sect->FSize);
    delete[] buf;
    nf.Save();
    pf.close();

    ifstream sfile("SigPatches.txt");
    if (sfile.is_open())
    {
        nf.seekp(0, ios_base::end);
        auto size = nf.tellg();
        vector<uint8_t> data;
        data.resize(size);
        nf.seekp(0);
        nf.read((char *)data.data(), size);
        string s, p;
        while (true)
        {
            if (!getline(sfile, s))
                break;
            if (s == "" || starts_with(s, "//"))
                continue;
            if (!getline(sfile, p))
                break;
            SigApply(data, s, p);
        }
        nf.seekp(0);
        nf.write((char *)data.data(), size);
    }
    nf.close();

    cout << "Done";
    return 0;
}
