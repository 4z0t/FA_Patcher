using namespace std;

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

#define ErrLog(str) \
    cerr << __FUNCTION__ << ":" << __LINE__ << str << "\n"

void CreateSectionWithAddresses(const string &base_file_name, const string &new_file_name, const unordered_map<int, string> &addresses)
{
    if (filesystem::exists(new_file_name))
        filesystem::remove(new_file_name);
    filesystem::copy_file(
        base_file_name,
        new_file_name,
        filesystem::copy_options::overwrite_existing | filesystem::copy_options::update_existing);
    ofstream new_file(new_file_name, ios::app);
    if (!new_file.is_open())
    {
        ErrLog("Couldn't open new section file " << new_file_name);
        return;
    }
    for (const auto &[addr, funcname] : addresses)
    {
        new_file << "_" << funcname << " = 0x" << hex << addr << ";\n";
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

bool starts_with(string str, const char *substr)
{
    return strncmp(str.c_str(), substr, strlen(substr)) == 0;
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

#define align(v, a) ((v) + ((a)-1)) & ~((a)-1)

int main()
{
    if (system("g++ --version"))
        return 1;

    ifstream f("config.txt");
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
        }
    }
    else
    {
        ofstream f("config.txt");
        f << "oldfile " << oldfile << "\n";
        f << "newfile " << newfile << "\n";
        f << "newsect " << newsect << "\n";
        f << "sectsize 0x" << hex << sectsize << "\n";
        f << "cflags " << cflags;
    }

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

    RemoveFiles("./build/", "*.*");
    _wmkdir(L"build");

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

    auto addresses = ExtractFunctionAddresses("./section/include/", "*.h");
    CreateSectionWithAddresses("./section.ld", "./new_section.ld", addresses);
    if (system(
            ("cd build && g++ " + cflags +
             " -Wl,-T,../new_section.ld,--image-base," +
             to_string(nf.imgbase + newVOffset - 0x1000) +
             ",-s,-Map,sectmap.txt ../section.cpp")
                .c_str()))
        return 1;

    ParseMap("build/sectmap.txt", "define.h");

    RemoveFiles("./build/", "*.o");

    if (system(("cd build && g++ -c " + cflags + " ../hooks/*.cpp").c_str()))
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

    if (system(
            ("ld -T patch.ld --image-base " +
             to_string(nf.imgbase) +
             " -s -Map build/patchmap.txt")
                .c_str()))
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
