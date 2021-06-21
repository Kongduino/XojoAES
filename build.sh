#!/bin/sh
gcc -c -g aes.c -o aes.o; gcc -dynamiclib aes.o -o aes.dylib; nm -gU  aes.dylib

