#!/bin/bash
OLD_PWD=$PWD

PACKAGE_DIR=$1
ARCH=$DUB_ARCH
BUILD_TYPE=$DUB_BUILD_TYPE

DEST_DIR=$PACKAGE_DIR/c/build/$ARCH-$BUILD_TYPE

if [ ! -d "$DEST_DIR" ]; then
    mkdir -p "$DEST_DIR"
fi

if [ -f "$PACKAGE_DIR/LzmaDec.o" ] && [ -z $DUB_FORCE ]; then
    exit
fi

cd "$PACKAGE_DIR/c"

gcc -c lzma/LzmaDec.c -o "$DEST_DIR/LzmaDec.o"

cd "$OLD_PWD"
