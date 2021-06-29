#!/bin/bash
OLD_PWD=$PWD

PACKAGE_DIR=$1

if [ ! -d "$PACKAGE_DIR/c/build" ]; then
    mkdir -p "$PACKAGE_DIR/c/build"
fi

if [ -f "$PACKAGE_DIR/c/build/LzmaDec.o" ]; then
    exit
fi

cd $PACKAGE_DIR/c

gcc -c lzma/LzmaDec.c -o build/LzmaDec.o

cd $OLD_PWD
