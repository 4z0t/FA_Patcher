g++ -c -Os -std=c++17 demangler.cpp -o demangler.o
g++ -c -Os -std=c++17 utility.cpp -o utility.o
g++ -c -Os -std=c++17 main.cpp -o main.o
g++ -c -Os -std=c++17 MapFunc.cpp -o MapFunc.o
g++ -c -Os -std=c++17 FunctionMapper.cpp -o FunctionMapper.o
g++ -pipe -static -s demangler.o utility.o FunctionMapper.o main.o -o FaP.exe
g++ -pipe -static -s demangler.o utility.o FunctionMapper.o MapFunc.o -o MapFunc.exe