g++ -c -Os -std=c++17 demangler.cpp -o demangler.o
g++ -c -Os -std=c++17 utility.cpp -o utility.o
g++ -c -Os -std=c++17 main.cpp -o main.o
g++ -c -Os -std=c++17 FunctionMapper.cpp -o FunctionMapper.o
g++ -pipe -static -s demangler.o utility.o FunctionMapper.o main.o -o FaP.exe
xcopy /y FaP.exe C:\Users\4z0t\GIT\fa_patch\FA-Binary-Patches\FaP.exe