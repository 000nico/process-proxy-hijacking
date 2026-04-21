// proxy.h
#pragma once
#include<windows.h>

extern DWORD targetPid;
extern HANDLE readThread;
extern HANDLE writeThread;
extern uintptr_t readBufferAddress;
extern uintptr_t writeBufferAddress;
extern uintptr_t structAddress;

extern LPVOID shellCodeReadRegion;
extern LPVOID shellCodeWriteRegion;
extern LPVOID readBufferRegion;
extern LPVOID writeBufferRegion;
extern LPVOID structRegion;

namespace proxy{
    bool enableSeDebugPrivilege();
    int findProcessWithHandle(ULONG accessMask, LPCSTR windowName, DWORD* processPIDBuffer, HANDLE* duplicatedHandleBuffer, USHORT* originalHandleValue);
    int findAddressWithHandle(HANDLE handle, DWORD pid, uintptr_t* foundAtAddress, LPCSTR windowName);
    int prepareCodeInjection(DWORD pid, LPVOID* rShellCodeBaseAddress, LPVOID* wShellCodeBaseAddress, LPVOID* rBufferBaseAddress, LPVOID* wBufferBaseAddress, LPVOID* structBaseAddress);
    int init(ULONG accessMask, LPCSTR windowName, bool debug);
    int exit(bool debug);
    int read(uintptr_t address, SIZE_T size);
    int write(uintptr_t address, uintptr_t value, SIZE_T size);
}

namespace payload{
    int load(DWORD pid, uintptr_t readShellCodeBaseAddress, uintptr_t handleAddress, uintptr_t readBufferAddress, uintptr_t structBaseAddress, uintptr_t writeShellCodeBaseAddress, uintptr_t writeBufferAddress);
    uintptr_t read(DWORD pid, uintptr_t address, uintptr_t addressOfReadBuffer, uintptr_t structBaseAddress, SIZE_T size);
    uintptr_t write(DWORD pid, uintptr_t address, uintptr_t valueToWrite, uintptr_t addressOfWriteBuffer, uintptr_t structBaseAddress, SIZE_T size);
}

// nt query system information import
typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

// system handle information
typedef struct {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct {
    ULONG Count;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

// types of access
enum accessType {
    TERMINATE         = 0x0001,
    CREATE_THREAD     = 0x0002,
    OPERATION         = 0x0008,
    READ              = 0x0010,
    WRITE             = 0x0020,
    DUP_HANDLE        = 0x0040,
    QUERY_INFORMATION = 0x0400,
    ALL_ACCESS        = 0x1FFFFF
};

// payload
typedef NTSTATUS (NTAPI *fnNtReadVirtualMemory_t)(
    HANDLE,    // ProcessHandle
    PVOID,     // BaseAddress
    PVOID,     // Buffer
    SIZE_T,    // NumberOfBytesToRead
    PSIZE_T    // NumberOfBytesRead
);

typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory_t)(
    HANDLE,    // ProcessHandle
    PVOID,     // BaseAddress
    PVOID,     // Buffer
    SIZE_T,    // NumberOfBytesToWrite
    PSIZE_T    // NumberOfBytesWritten
);

struct payloadStruct {
    // both
    uintptr_t handleAddress;
    uintptr_t targetAddress;
    SIZE_T size;

    // read
    uintptr_t readBuffer;
    fnNtReadVirtualMemory_t read;
    volatile int readSignal;

    // write
    fnNtWriteVirtualMemory_t write;
    uintptr_t writeBuffer;
    volatile int writeSignal;
};