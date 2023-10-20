using namespace std;

#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <cstdint>
#include <vector>
#include <regex>
#include <io.h>

#define ErrLog(str) \
    cerr << __FUNCTION__ << ":" << __LINE__ << str << "\n"

void RemoveFiles(const string &dir, const char *mask) {
    _finddata_t data;
    int hf = _findfirst((dir + mask).c_str(), &data);
    if (hf < 0) return;
    do {
        remove((dir + data.name).c_str());
    } while (_findnext(hf, &data) != -1);
    _findclose(hf);
}

bool starts_with(string str, const char *substr) {
    return strncmp(str.c_str(), substr, strlen(substr)) == 0;
}

void ParseMap(const char *mapfile, const char *outfile) {
    ifstream ifile(mapfile);
    ofstream ofile(outfile);
    ofile << "#define QUAUX(X) #X\n#define QU(X) QUAUX(X)\n\n";
    string l;
    bool need = false;
    while (getline(ifile, l)) {
        if (starts_with(l, " .text.startup "))
            ofile << "#define STARTUP " << l.substr(16, 10) << "\n"; else
        if (starts_with(l, " .text ") ||
            starts_with(l, " .data ") ||
            starts_with(l, " .bss ")) {
            need = true;
            continue;
        }
        if (need && starts_with(l, "  ")) {
            int i = l.find("(");
            if (i > 0) l.resize(i);
            stringstream ss(l);
            string w, w2;
            ss >> w; ss >> w2;
            ofile << "#define " << w2 << " " << w << "\n";
            continue;
        }
        need = false;
    }
    ofile.close();
}

struct PESect {
    char name[8];
    int32_t VSize, VOffset, FSize, FOffset;
    char pad[12];
    uint32_t Flags;
};

class PEFile : public fstream {
  public:
    uint32_t offset, imgbase, sectalign, filealign;
    vector<PESect> sects;

    PEFile(string filename);
    PESect* FindSect(const char *name);
    void Save();
};

PEFile::PEFile(string filename) : fstream(filename, binary | in | out) {
    if (!is_open()) {
        ErrLog(" -> Failed to open " << filename);
        return;
    }
    seekp(0x3c);
    read((char*)&offset, sizeof(offset));
    uint16_t scnt;
    seekp(offset+0x6);
    read((char*)&scnt, sizeof(scnt));
    sects.resize(scnt);
    seekp(offset+0x34);
    read((char*)&imgbase, sizeof(imgbase) * 3);
    seekp(offset+0xf8);
    read((char*)sects.data(), sizeof(PESect) * scnt);
}

PESect* PEFile::FindSect(const char *name) {
    for (int i = 0; i < sects.size(); i++)
        if (strcmp(name, (const char*)&sects[i].name) == 0)
            return &sects[i];
    return NULL;
}

void PEFile::Save() {
    uint16_t scnt = sects.size();
    seekp(offset+0x6);
    write((char*)&scnt, sizeof(scnt));
    uint32_t imgsize = sects.back().VOffset + sects.back().VSize;
    seekp(offset+0x50);
    write((char*)&imgsize, sizeof(imgsize));
    seekp(offset+0xf8);
    write((char*)sects.data(), sizeof(PESect) * scnt);
}

struct COFFSect {
    char name[8];
    uint32_t size, offset;
};

class COFFFile {
  public:
    string name;
    vector<COFFSect> sects;

    COFFFile(string filename);
    COFFSect* FindSect(const char *name);
};

COFFFile::COFFFile(string filename) {
    fstream f(filename, ios::binary | ios::in | ios::out);
    if (!f.is_open()) {
        ErrLog(" -> Failed to open " << filename);
        return;
    }
    name = filename;
    f.seekg(2);
    uint16_t scnt;
    f.read((char*)&scnt, sizeof(scnt));
    f.seekg(20);
    for (int i = 0; i < scnt; i++) {
        char data[8];
        f.read(data, sizeof(data));
        if (data[0] == 'h') {
            sects.push_back({});
            COFFSect* sect = &sects.back();
            memcpy(sect->name, data, sizeof(sect->name));
        }
        f.seekg(0x20, ios_base::cur);
    }
    f.seekg(8);
    uint32_t pos, cnt;
    f.read((char*)&pos, sizeof(pos));
    f.read((char*)&cnt, sizeof(cnt));
    f.seekg(pos);
    for (int i = 0; i < cnt; i++) {
        char data[18];
        f.read(data, sizeof(data));
        COFFSect* sect = FindSect(data);
        if (!sect) {
            f.seekg(sizeof(data) * data[17], ios_base::cur);
            i += data[17];
            continue;
        }
        if (data[17] > 0) {
            f.read(data, sizeof(data));
            sect->size = *(uint32_t*)&data[0];
            i++; continue;
        }
        sect->offset = *(uint32_t*)&data[8];
    }
    f.seekg(20);
    for (int i = 0; i < scnt; i++) {
        char data[8];
        f.read(data, sizeof(data));
        COFFSect* sect = FindSect(data);
        if (sect) {
            f.seekp(f.tellg() + 8LL);
            f.write((char*)&sect->size, sizeof(sect->size));
            continue;
        }
        f.seekg(0x20, ios_base::cur);
    }
    f.close();
}

COFFSect* COFFFile::FindSect(const char *name) {
    for (int i = 0; i < sects.size(); i++)
        if (strcmp(name, (const char*)&sects[i].name) == 0)
            return &sects[i];
    return NULL;
}

void MakeLists(const string &dir, const char *mask, ofstream &ret) {
    string path = dir + mask;
    _finddata_t fdata;
    int hf = _findfirst(path.c_str(), &fdata);
    if (hf < 0) {
        ErrLog(" -> No files matching the pattern: " << path);
        return;
    }
    regex pattern(R"(PatcherList_([a-zA-Z][a-zA-Z0-9]*)_?([a-zA-Z_]\w*)?)");
    unordered_map<string, unordered_set<string>> lists;
    do {
        path = dir + fdata.name;
        ifstream src(path.c_str());
        if (!src.is_open()) {
            ErrLog(" -> Failed to open " << path);
            continue;
        }
        string l;
        smatch match;
        while (getline(src, l))
            if (regex_search(l, match, pattern))
                if (match[2] == "")
                    lists[match[1]]; else
                    lists[match[1]].insert(match[2]);
        src.close();
    } while (_findnext(hf, &fdata) != -1);
    _findclose(hf);
    for (const auto& [listName, elems] : lists) {
        ret << "void* " << listName << "[] = {";
        for (const auto& elem : elems)
            ret << "&" << elem << ", ";
        ret << "0};\n";
    }
}

void SigApply(vector<uint8_t> &data, string sig, string patch) {
    auto strToBytes = [](string &str, vector<uint8_t> &bytes, vector<bool> &mask) {
        str.erase(remove(str.begin(), str.end(), ' '), str.end());
        for (size_t i = 0; i < str.length(); i += 2) {
            string byteStr = str.substr(i, 2);
            if (byteStr != "??") {
                uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
                bytes.push_back(byte);
                mask.push_back(true);
            } else {
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
    for (size_t i = 0; i <= data.size() - sigSize; i++) {
        bool sigFound = true;
        for (size_t j = 0; j < sigSize; j++)
            if (sigMask[j])
                if (data[i + j] != sigBytes[j]) {
                    sigFound = false;
                    break;
                }
        if (!sigFound) continue;
        for (size_t j = 0; j < patchSize; j++)
            if (patchMask[j])
                data[i + j] = patchBytes[j];
        i += sigSize - 1;
        patched++;
    }
    cout << "Signature: " << sig << "\tPatched: " << patched << " times" << "\n";
}

string oldfile("ForgedAlliance_base.exe");
string newfile("ForgedAlliance_exxt.exe");
string newsect(".exxt");
uint32_t sectsize = 0x80000;
string cflags("-pipe -m32 -Os -nostartfiles -w -fpermissive -masm=intel -std=c++20 -march=core2 -mfpmath=both");

#define align(v, a) ((v) + ((a) - 1)) & ~((a) - 1)

int main() {
    if (system("g++ --version")) return 1;

    ifstream f("config.txt");
    if (f.is_open()) {
        string l;
        while (getline(f, l)) {
            stringstream ss(l);
            ss >> l;
            if (l == "oldfile")
                ss >> oldfile; else
            if (l == "newfile")
                ss >> newfile; else
            if (l == "newsect")
                ss >> newsect; else
            if (l == "sectsize")
                ss >> hex >> sectsize; else
            if (l == "cflags")
                getline(ss, cflags);
        }
    } else {
        ofstream f("config.txt");
        f << "oldfile " << oldfile << "\n";
        f << "newfile " << newfile << "\n";
        f << "newsect " << newsect << "\n";
        f << "sectsize 0x" << hex << sectsize << "\n";
        f << "cflags " << cflags;
    }

    ifstream src(oldfile, ios::binary);
    if (!src.is_open()) {
        ErrLog(" -> Failed to open " << oldfile);
        return 1;
    }
    ofstream dst(newfile, ios::binary);
    if (!dst.is_open()) {
        ErrLog(" -> Failed to create " << newfile);
        return 1;
    }
    dst << src.rdbuf();
    dst.close(); src.close();

    RemoveFiles("./build/", "*.*");
    _wmkdir(L"build");

    PEFile nf(newfile);
    if (nf.FindSect(newsect.c_str())) {
        ErrLog(" -> Section already exists: " << newsect);
        return 1;
    }
    int newVOffset = 0, newFOffset = 0;
    for (int i = 0; i < nf.sects.size(); i++) {
        PESect* sect = &nf.sects[i];
        uint32_t lastOffset;
        lastOffset = sect->VOffset + sect->VSize;
        if (lastOffset > newVOffset) newVOffset = lastOffset;
        lastOffset = sect->FOffset + sect->FSize;
        if (lastOffset > newFOffset) newFOffset = lastOffset;
    }
    newVOffset = align(newVOffset, nf.sectalign);
    newFOffset = align(newFOffset, nf.filealign);

    ofstream smain("section.cpp");
    _finddata_t fdata;
    int hf = _findfirst("./section/*.cpp", &fdata);
    do {
        smain << "#include \"section/" << fdata.name << "\"\n";
    } while (_findnext(hf, &fdata) != -1);
    _findclose(hf);
    MakeLists("./section/", "*.cpp", smain);
    smain.close();

    #define sectVAddr to_string(nf.imgbase + newVOffset - 0x1000)
    if (system(("cd build && g++ " + cflags + "\
      -Wl,-T,../section.ld,--image-base,"+ sectVAddr +",-s,-Map,sectmap.txt ../section.cpp").c_str())) return 1;

    ParseMap("build/sectmap.txt", "define.h");

    RemoveFiles("./build/", "*.o");

    if (system(("cd build && g++ -c "+ cflags +" ../hooks/*.cpp").c_str())) return 1;

    ofstream pld("patch.ld");
    pld << "OUTPUT_FORMAT(pei-i386)\n" << "OUTPUT(build/patch.pe)\n" << "SECTIONS {\n";

    vector<COFFFile> hooks;
    hf = _findfirst("./build/*.o", &fdata);
    do {
        auto coff = COFFFile(string("build/") + fdata.name);
        bool valid = false;
        for (auto &sect : coff.sects) {
            string s = ": " + string(fdata.name) + ' ' + sect.name + '\n';
            if (sect.name[7])
                cout << "Hook name too long" << s; else
            if (!sect.size)
                cout << "Hook invalid size" << s; else
            if (sect.offset < nf.imgbase)
                cout << "Hook invalid offset" << s; else
                valid = true;
        }
        if (valid)
            hooks.push_back(coff);
    } while (_findnext(hf, &fdata) != -1);
    _findclose(hf);

    int hi = 0;
    for (int i = 0; i < hooks.size(); i++) {
        COFFFile *hf = &hooks[i];
        for (int i = 0; i < hf->sects.size(); i++) {
            COFFSect *sect = &hf->sects[i];
            pld << "  .h" << to_string(hi++) << " 0x" << hex << sect->offset;
            pld << " : SUBALIGN(1) {\n    " << hf->name << "("<< sect->name << ")\n  }\n";
        }
    }

    PEFile sf("build/section.pe");
    size_t ssize = sf.sects.back().VOffset + sf.sects.back().VSize - sf.sects[0].VOffset;

    pld << "  " << newsect << " 0x" << hex << nf.imgbase + newVOffset << ": {\n\
    . = . + "+ to_string(ssize) +";\n    *(.data)\n    *(.bss)\n    *(.rdata)\n  }\n";
    pld << "  /DISCARD/ : {\n    *(.text)\n    *(.text.startup)\n\
    *(.rdata$zzz)\n    *(.eh_frame)\n    *(.ctors)\n    *(.reloc)\n  }\n}";
    pld.close();

    if (system(("ld -T patch.ld --image-base " + to_string(nf.imgbase) +
      " -s -Map build/patchmap.txt").c_str())) return 1;

    PEFile pf("build/patch.pe");
    hi = 0;
    for (int i = 0; i < hooks.size(); i++) {
        COFFFile *hf = &hooks[i];
        if (hf->sects.empty())
            cout << "No hooks in " << hf->name << '\n';
        for (int i = 0; i < hf->sects.size(); i++) {
            PESect* psect = pf.FindSect((".h" + to_string(hi++)).c_str());
            uint32_t size = hf->sects[i].size;
            char* buf = (char*)malloc(size);
            pf.seekp(psect->FOffset);
            pf.read(buf, size);
            nf.seekp(psect->VOffset);
            nf.write(buf, size);
            free(buf);
        }
    }

    PESect* sect = pf.FindSect(newsect.c_str());
    nf.sects.push_back(*sect);
    PESect* nsect = &nf.sects.back();
    nsect->VOffset = newVOffset;
    nsect->FOffset = newFOffset;
    if (sectsize > 0) {
        if (sectsize < sect->FSize) {
            ErrLog(" -> Section size too small. Required: 0x" << hex << sect->FSize);
            return 1;
        }
        sect->VSize = sectsize;
        sect->FSize = sectsize;
    }
    char* buf = (char*)malloc(sect->FSize);
    pf.seekp(sect->FOffset);
    pf.read(buf, sect->FSize);
    nf.seekp(nsect->FOffset);
    nf.write(buf, sect->FSize);
    free(buf);
    for (auto &s : sf.sects) {
        char* buf = (char*)malloc(s.FSize);
        sf.seekp(s.FOffset);
        sf.read(buf, s.FSize);
        nf.seekp(nsect->FOffset + s.VOffset - sf.sects[0].VOffset);
        nf.write(buf, s.FSize);
        free(buf);
    }
    nf.Save();
    pf.close();

    ifstream sfile("SigPatches.txt");
    if (sfile.is_open()) {
        nf.seekp(0, ios_base::end);
        auto size = nf.tellg();
        vector<uint8_t> data;
        data.resize(size);
        nf.seekp(0);
        nf.read((char*)data.data(), size);
        string s, p;
        while (true) {
            if (!getline(sfile, s)) break;
            if (s == "" || starts_with(s, "//")) continue;
            if (!getline(sfile, p)) break;
            SigApply(data, s, p);
        }
        nf.seekp(0);
        nf.write((char*)data.data(), size);
    }
    nf.close();

    cout << "Done";
    return 0;
}