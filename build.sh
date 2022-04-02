#!/bin/bash

CXX="${CXX:-gcc}"
SRC_APP="*.c"
FLAGS="-Wall -Werror -Wextra -pedantic -ggdb -lm"
LIBS=""
OUT="aes"

if [[ -z "$LIB" ]]
then
    $CXX $SRC_APP $FLAGS -o $OUT
else
    $CXX $SRC_APP $FLAGS -o $OUT $(pkg-config --cflags --libs $LIBS)
fi

if [[ $? -ne 0 ]]
then
    echo "ERROR: Compile failed!"
    exit 1
else
    echo "Compile succesfully!"
    exit 0
fi
