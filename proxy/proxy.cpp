// proxy.cpp
#include <vector>
#include <windows.h>
#include <wingdi.h>
#include <winnt.h>
#include <winuser.h>
#include <iostream>

#include "proxy.h"

#include "../payload/read/bin/shellcodeRead.h"
#include "../payload/write/bin/shellcodeWrite.h"

#pragma comment(lib, "ntdll")

uintptr_t readBufferAddress = 0;
uintptr_t writeBufferAddress = 0;
uintptr_t structAddress = 0;
DWORD targetPid = 0;
HANDLE readThread = 0;
HANDLE writeThread = 0;
LPVOID shellCodeReadRegion = 0;
LPVOID shellCodeWriteRegion = 0;
LPVOID readBufferRegion = 0;
LPVOID writeBufferRegion = 0;
LPVOID structRegion = 0;

bool proxy::enableSeDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp = { 1 };
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return false;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

int proxy::findProcessWithHandle(ULONG accessMask, LPCSTR windowName, DWORD* processPIDBuffer, HANDLE* duplicatedHandleBuffer, USHORT* originalHandleValue){
    HWND hwnd = FindWindowA(nullptr, windowName);

    if(!hwnd)
        return 0;

    DWORD windowPid;
    GetWindowThreadProcessId(hwnd, &windowPid);

    if(!windowPid)
        return 0;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if(!NtQuerySystemInformation)
        return 0;

    BYTE buffer[1048576]; // 1MB
    NTSTATUS NtQSI = NtQuerySystemInformation(0x10, buffer, sizeof(buffer), NULL); // 0x10 = SYSTEM HANDLE INFORMATION

    if(!NtQSI)
        return 0;

    SYSTEM_HANDLE_INFORMATION* SystemHandleInformation = (SYSTEM_HANDLE_INFORMATION*)buffer;

    for(int i = 0;  i < SystemHandleInformation->Count; i++){
        if((SystemHandleInformation->Handles[i].GrantedAccess & accessMask) == accessMask){
            // see which process the handle points to
            HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, SystemHandleInformation->Handles[i].UniqueProcessId);

            HANDLE duplicatedHandle = NULL;
            
            DuplicateHandle(handle, (HANDLE)(ULONG_PTR)SystemHandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);

            DWORD pid = GetProcessId(duplicatedHandle);

            if(GetProcessId(duplicatedHandle) == windowPid){
                if(duplicatedHandleBuffer)
                    *duplicatedHandleBuffer = duplicatedHandle;

                if(processPIDBuffer)
                    *processPIDBuffer = SystemHandleInformation->Handles[i].UniqueProcessId;

                if(originalHandleValue)
                    *originalHandleValue = SystemHandleInformation->Handles[i].HandleValue;
                    
                targetPid = SystemHandleInformation->Handles[i].UniqueProcessId;
                CloseHandle(handle);
                return 1;
            }
            if(duplicatedHandle) 
                CloseHandle(duplicatedHandle);

            CloseHandle(handle);
        }
    }
    return 0;
}

int proxy::findAddressWithHandle(HANDLE handle, DWORD pid, uintptr_t* foundAtAddress, LPCSTR windowName){
    HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    ULONG_PTR address = (ULONG_PTR)sysInfo.lpMinimumApplicationAddress;
    ULONG_PTR maxAddress = (ULONG_PTR)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    std::vector<BYTE> buffer;

    HWND gameHWND = FindWindowA(nullptr, windowName);

    if(!gameHWND)
        return 0;


    DWORD gamePID;
    GetWindowThreadProcessId(gameHWND, &gamePID);

    if(!gamePID)
        return 0;
                 
    // the code below can be a little tricky to read, so i commented it
    while(address < maxAddress){ // while we dont reach the max address of the process
        VirtualQueryEx(targetHandle, (LPCVOID)address, &mbi, sizeof(mbi)); // receive in "mbi" the info of the memory region (from the address, VirtualQueryEx gives us info of the region)

        if(mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)){ // if the region is valid
            buffer.resize(mbi.RegionSize); // copy the region in our buffer
            SIZE_T bytesRead = 0;

            if(ReadProcessMemory(targetHandle, (LPCVOID)address, buffer.data(), mbi.RegionSize, &bytesRead)){ // give the buffer a value
                // search for handle in buffer
                for (SIZE_T i = 0; i + sizeof(ULONG_PTR) <= bytesRead; i += sizeof(ULONG_PTR)) { // read from 8 to 8
                    HANDLE found = *(HANDLE*)(buffer.data() + i); // reads 8 bytes in the pos "i" and interprets it like a HANDLE

                    if (found == handle) { // if what we found equals the handle given by parameter
                        HANDLE dupedHandle = NULL;
                        BOOL ok = DuplicateHandle(targetHandle, found, GetCurrentProcess(), &dupedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS); // dup the handle

                        if(ok && dupedHandle){ 
                            if(gamePID == GetProcessId(dupedHandle)){ // and if the handle points to our game, we found it
                                if(foundAtAddress){
                                    *foundAtAddress = address + i;

                                    CloseHandle(dupedHandle); 
                                    CloseHandle(targetHandle);
                                    return 1;
                                }
                            }
                            CloseHandle(dupedHandle); 
                        }
                    }
                }
            }
        }
        address += mbi.RegionSize;
    }

    CloseHandle(targetHandle);
    return 0;
}

int proxy::prepareCodeInjection(DWORD pid, LPVOID* rShellCodeBaseAddress, LPVOID* wShellCodeBaseAddress, LPVOID* rBufferBaseAddress, LPVOID* wBufferBaseAddress, LPVOID* structBaseAddress){
    HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    shellCodeReadRegion = VirtualAllocEx(targetHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // 0x1000 = 1 page
    shellCodeWriteRegion = VirtualAllocEx(targetHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    readBufferRegion = VirtualAllocEx(targetHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
    writeBufferRegion = VirtualAllocEx(targetHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
    structRegion = VirtualAllocEx(targetHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 

    if(!shellCodeReadRegion || !shellCodeWriteRegion || !readBufferRegion || !writeBufferRegion || !structRegion) 
        return 0;

    readBufferAddress = (uintptr_t)readBufferRegion;
    writeBufferAddress = (uintptr_t)writeBufferRegion;
    structAddress = (uintptr_t)structRegion;

    if(rShellCodeBaseAddress)
        *rShellCodeBaseAddress = shellCodeReadRegion;

    if(wShellCodeBaseAddress)
        *wShellCodeBaseAddress = shellCodeWriteRegion;

    if(rBufferBaseAddress)
        *rBufferBaseAddress = readBufferRegion;
        
    if(wBufferBaseAddress)
        *wBufferBaseAddress = writeBufferRegion;

    if(structBaseAddress)
        *structBaseAddress = structRegion;
    
    CloseHandle(targetHandle);
    return 1;
}

int payload::load(DWORD pid, uintptr_t readShellCodeBaseAddress, uintptr_t handleAddress, uintptr_t readBufferAddress, uintptr_t structBaseAddress, uintptr_t writeShellCodeBaseAddress, uintptr_t writeBufferAddress){
    HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // write shell code
    if(!WriteProcessMemory(targetHandle, (LPVOID)readShellCodeBaseAddress, bin_shellcodeRead_bin, bin_shellcodeRead_bin_len, 0))
        return 0;

    if(!WriteProcessMemory(targetHandle, (LPVOID)writeShellCodeBaseAddress, bin_shellcodeWrite_bin, bin_shellcodeWrite_bin_len, 0))
        return 0;

    // write payload struct
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    payloadStruct pd = {};
    pd.handleAddress = handleAddress;

    pd.readBuffer = readBufferAddress;
    pd.readSignal = 0;
    pd.read = (fnNtReadVirtualMemory_t) GetProcAddress(ntdll, "NtReadVirtualMemory");

    pd.writeBuffer = writeBufferAddress;
    pd.writeSignal = 0;
    pd.write = (fnNtWriteVirtualMemory_t) GetProcAddress(ntdll, "NtWriteVirtualMemory");

    // write payload on memory
    if(!WriteProcessMemory(targetHandle, (LPVOID)structBaseAddress, &pd, sizeof(pd), 0))
        return 0;

    // create thread
    readThread = CreateRemoteThread(targetHandle, NULL, 0, (LPTHREAD_START_ROUTINE)readShellCodeBaseAddress, (LPVOID)structBaseAddress, 0, NULL);
    writeThread = CreateRemoteThread(targetHandle, NULL, 0, (LPTHREAD_START_ROUTINE)writeShellCodeBaseAddress, (LPVOID)structBaseAddress, 0, NULL);

    CloseHandle(targetHandle);

    if(!readThread || !writeThread)
        return 0;

    return 1;
}

uintptr_t payload::read(DWORD pid, uintptr_t address, uintptr_t addressOfReadBuffer, uintptr_t structBaseAddress) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // read the actual struct and send signal
    payloadStruct pd = {};
    ReadProcessMemory(targetHandle, (LPVOID)structBaseAddress, &pd, sizeof(pd), 0);
    pd.targetAddress = address;
    pd.readSignal = 1;
    WriteProcessMemory(targetHandle, (LPVOID)structBaseAddress, &pd, sizeof(pd), 0);

    // wait for payload to finish
    int signal = 1;
    while(signal){
        ReadProcessMemory(targetHandle, (LPVOID)structBaseAddress, &pd, sizeof(pd), 0);
        signal = pd.readSignal;
    }

    // catch the readed data in the read buffer
    uintptr_t result;
    
    if(ReadProcessMemory(targetHandle, (LPVOID)addressOfReadBuffer, &result, sizeof(DWORD), 0)){
        CloseHandle(targetHandle);
        return result;
    }

    CloseHandle(targetHandle);
    return 0;
}

uintptr_t payload::write(DWORD pid, uintptr_t address, uintptr_t valueToWrite, uintptr_t addressOfWriteBuffer, uintptr_t structBaseAddress){
    HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    WriteProcessMemory(targetHandle, (LPVOID)addressOfWriteBuffer, &valueToWrite, sizeof(DWORD), 0);

    // read the actual struct and send signal
    payloadStruct pd = {};
    ReadProcessMemory(targetHandle, (LPVOID)structBaseAddress, &pd, sizeof(pd), 0);
    pd.targetAddress = address;
    pd.writeSignal = 1;
    WriteProcessMemory(targetHandle, (LPVOID)structBaseAddress, &pd, sizeof(pd), 0);

    int signal = 1;
    while(signal){
        ReadProcessMemory(targetHandle, (LPVOID)structBaseAddress, &pd, sizeof(pd), 0);
        signal = pd.writeSignal;
    }

    CloseHandle(targetHandle);
    return 1;
}

int proxy::init(ULONG accessMask, LPCSTR windowName, bool debug){
    if(!enableSeDebugPrivilege()){
        if(debug)
            std::cout << "[proxy] failed at enabling privilege" << std::endl;

        return 2;
    }

    else if(debug){
        std::cout << "[proxy] privilege enabled" << std::endl;
    }

    DWORD targetProcessPID;
    USHORT originalHandle;
    if(!proxy::findProcessWithHandle(accessMask, windowName, &targetProcessPID, 0, &originalHandle)){
        if(debug)
            std::cout << "[proxy] failed at finding a process with the desired handle" << std::endl;

        return 3;
    }

    else if(debug){
        std::cout << "[proxy] found the handle " << originalHandle << " in the process with PID " << targetProcessPID << std::endl; 
    }

    uintptr_t handleAddress;
    if(!proxy::findAddressWithHandle((HANDLE)(uintptr_t)originalHandle, targetProcessPID, &handleAddress, windowName)){
        if(debug)
            std::cout << "[proxy] failed at finding the address of the handle" << std::endl;

        return 4;
    }
    
    else if(debug){
        std::cout << "[proxy] found the handle " << originalHandle << " in the address 0x" << std::hex << handleAddress << std::dec << " of the process with PID " << targetProcessPID << std::endl;
    }

    LPVOID readShellCodeBaseAddress, writeShellCodeBaseAddress, readBufferBaseAddress, writeBufferBaseAddress, structBaseAddress;
    if(!proxy::prepareCodeInjection(targetProcessPID, &readShellCodeBaseAddress, &writeShellCodeBaseAddress, &readBufferBaseAddress, &writeBufferBaseAddress, &structBaseAddress)){
        if(debug)
            std::cout << "[proxy] failed at preparing the code injection" << std::endl;
            
        return 5;
    }
        

    else if(debug){
        std::cout << "[proxy] successfully allocated four memory pages in the process with PID " << targetProcessPID << std::endl;
        std::cout << "[proxy] read shell code base address: " << readShellCodeBaseAddress << std::endl;
        std::cout << "[proxy] write shell code base address: " << writeShellCodeBaseAddress << std::endl;
        std::cout << "[proxy] read buffer base address: " << readBufferBaseAddress << std::endl;
        std::cout << "[proxy] write buffer base address: " << writeBufferBaseAddress << std::endl;
        std::cout << "[proxy] struct base address: " << structBaseAddress << std::endl;
    }

    if(!payload::load(targetProcessPID, (uintptr_t)readShellCodeBaseAddress, handleAddress, (uintptr_t)readBufferBaseAddress, (uintptr_t)structBaseAddress, (uintptr_t)writeShellCodeBaseAddress, uintptr_t(writeBufferBaseAddress))){
        if(debug)
            std::cout << "[payload] failed at injecting the payload" << std::endl;
        return 6;
    }
        

    else if(debug){
        std::cout << "[payload] successfully writted shell code" << std::endl;
        std::cout << "[payload] successfully writted struct" << std::endl;
        std::cout << "[payload] successfully created read and write threads" << std::endl;
        std::cout << "[payload] successfully injected" << std::endl;
    }

    // prepared to read now
    return 1;
}

int proxy::exit(bool debug){
    BOOL t1 = TerminateThread(readThread, 0);
    BOOL t2 = TerminateThread(writeThread, 0);
    if(debug) std::cout << "[exit] TerminateThread read: " << t1 << " write: " << t2 << std::endl;

    CloseHandle(readThread);
    CloseHandle(writeThread);

    HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
    if(debug) std::cout << "[exit] OpenProcess: " << targetHandle << std::endl;

    BOOL f1 = VirtualFreeEx(targetHandle, shellCodeReadRegion, 0, MEM_RELEASE);
    BOOL f2 = VirtualFreeEx(targetHandle, shellCodeWriteRegion, 0, MEM_RELEASE);
    BOOL f3 = VirtualFreeEx(targetHandle, readBufferRegion, 0, MEM_RELEASE);
    BOOL f4 = VirtualFreeEx(targetHandle, writeBufferRegion, 0, MEM_RELEASE);
    BOOL f5 = VirtualFreeEx(targetHandle, structRegion, 0, MEM_RELEASE);
    if(debug) std::cout << "[exit] VirtualFreeEx: " << f1 << f2 << f3 << f4 << f5 << std::endl;

    CloseHandle(targetHandle);
    return 1;
}

int proxy::read(uintptr_t address){
    int result = payload::read(targetPid, address, readBufferAddress, structAddress);
    return result;
}

int proxy::write(uintptr_t address, uintptr_t value){
    int result = payload::write(targetPid, address, value, writeBufferAddress, structAddress);
    return result;
}