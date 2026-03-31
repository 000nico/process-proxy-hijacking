#include "../proxy/proxy.h"
#include <cstdint>
#include <handleapi.h>
#include <iostream>
#include <minwindef.h>

int main(){
    proxy::init(QUERY_INFORMATION | OPERATION | READ | WRITE | DUP_HANDLE, "Counter-Strike 2", TRUE);

    // read test
    uintptr_t resultRead = proxy::read(0x0012D0C4);
    std::cout << "[read] " << resultRead << std::endl;

    // write test
    uintptr_t write = proxy::write(0x00133844, 822);
    uintptr_t resultWrite = proxy::read(0x00133844);
    std::cout << "[write] " << resultWrite << std::endl;
    
    proxy::exit(TRUE);
}

int manualProxyUsage(){
    // 0. enable privilege
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    proxy::enableSeDebugPrivilege();
    std::cout << "privilege ok" << std::endl;
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // 1. find the process with our desired handle
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    DWORD target;
    HANDLE dupHandle;
    USHORT originalHandle;
    int r = proxy::findProcessWithHandle(QUERY_INFORMATION | OPERATION | READ | WRITE | DUP_HANDLE, "Counter-Strike 2", &target, &dupHandle, &originalHandle);
    
    if(!r)
        std::cout << "error" << std::endl;

    else{
        std::cout << "process with the handle: " << target << std::endl;
        std::cout << "duped handle: " << dupHandle << std::endl;
        std::cout << "original handle: 0x" << std::hex << originalHandle << std::endl;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // 2. find in what address the process holds our desired handle
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    uintptr_t handleAddress;
    int r2 = proxy::findAddressWithHandle((HANDLE)(uintptr_t)originalHandle, target, &handleAddress, "Counter-Strike 2");

    if(!r2)
        std::cout << "error 2" << std::endl;
    else
        std::cout << "original handle is at the address 0x" << std::hex << handleAddress << " of the process with pid " << std::dec << target << std::endl;
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    // 3. alloc memory for the buffers and payloads
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    LPVOID readBaseAddress, writeBaseAddress, readBufferBaseAddress, writeBufferBaseAddress, structBaseAddress;
    int r3 = proxy::prepareCodeInjection(target, &readBaseAddress, &writeBaseAddress, &readBufferBaseAddress, &writeBufferBaseAddress, &structBaseAddress);

    if(!r3)
        std::cout << "error 3" << std::endl;
    else{
        std::cout << "successfully allocated three pages in the memory of the process with pid " << target << std::endl;
        std::cout << "read shell code base address: " << readBaseAddress << std::endl;
        std::cout << "write shell code base address: " << writeBaseAddress << std::endl;
        std::cout << "read buffer base address: " << readBufferBaseAddress << std::endl;
        std::cout << "write buffer base address: " << writeBufferBaseAddress << std::endl;
        std::cout << "struct base address: " << structBaseAddress << std::endl;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // 4. load the payload
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    int r4 = payload::load(target, (uintptr_t)readBaseAddress, handleAddress, (uintptr_t)readBufferBaseAddress, (uintptr_t)structBaseAddress, (uintptr_t)writeBaseAddress, (uintptr_t)writeBufferBaseAddress);

    if(!r4)
        std::cout << "error 4" << std::endl;

    else{
        std::cout << "payload injected" << std::endl;
    }

    // 5. try reading
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    int r5 = payload::read(target, 0x022CC904, (uintptr_t)readBufferBaseAddress, (uintptr_t)structBaseAddress);
    
    if(!r5)
        std::cout << "error 5" << std::endl;

    else{
        std::cout << "readed the value " << r5 << std::endl;
    }

    CloseHandle(dupHandle);

    proxy::exit(TRUE);

    return 1;
}