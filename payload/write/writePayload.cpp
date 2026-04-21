// writePayload.cpp
#include <windows.h>
#include "../../proxy/proxy.h"

void pWriteMem(payloadStruct* data){
    while(true){
        if(data->writeSignal){
            HANDLE handle = *(HANDLE*) data->handleAddress;

            data->write(handle, (PVOID)data->targetAddress, (PVOID)data->writeBuffer, data->size, nullptr);

            data->writeSignal = 0;
        }
    }
}