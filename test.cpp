#define ADDR(addr)

int a = 9;
extern "C"
{
    ADDR(0x01234567)
    void __cdecl lua_pcall(int b);
    ADDR(0x89ABCDEF)
    void __cdecl lua_pcall();
    ADDR(0x00000011)
    void __cdecl lua_toboolean(int a);
    void __cdecl lua_toboolean();
};