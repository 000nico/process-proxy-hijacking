#!/bin/bash

mkdir -p bin

x86_64-w64-mingw32-g++ \
    -O1 \
    -nostdlib \
    -fno-stack-protector \
    -fno-exceptions \
    -fno-rtti \
    -fPIC \
    -c writePayload.cpp -o bin/writePayload.o

objcopy -O binary --only-section=.text bin/writePayload.o bin/shellcodeWrite.bin

xxd -i bin/shellcodeWrite.bin | sed 's/unsigned char/static unsigned char/g; s/unsigned int/static unsigned int/g' > bin/shellcodeWrite.h

echo "Listo - $(wc -c < bin/shellcodeWrite.bin) bytes"