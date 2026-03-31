#!/bin/bash

mkdir -p bin

x86_64-w64-mingw32-g++ \
    -O1 \
    -nostdlib \
    -fno-stack-protector \
    -fno-exceptions \
    -fno-rtti \
    -fPIC \
    -c readPayload.cpp -o bin/readPayload.o

objcopy -O binary --only-section=.text bin/readPayload.o bin/shellcodeRead.bin

xxd -i bin/shellcodeRead.bin > bin/shellcodeRead.h

echo "finished! - $(wc -c < bin/shellcodeRead.bin) bytes"