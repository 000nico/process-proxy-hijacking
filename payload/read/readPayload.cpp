// readPayload.cpp
#include <cstdint>
#include <windows.h>
#include "../../proxy/proxy.h"

void pReadMem(payloadStruct* data){
    while(true){
        if(data->readSignal){
            HANDLE handle = *(HANDLE*) data->handleAddress;

            uintptr_t buffer;
            data->read(handle, (PVOID)data->targetAddress, (LPVOID)data->readBuffer, sizeof(DWORD), nullptr);

            data->readSignal = 0;
        }
    }
}