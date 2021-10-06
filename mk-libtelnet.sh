#! /usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

CC=musl-gcc

set -e
pushd libtelnet-0.23

export C_INCLUDE_PATH="$C_INCLUDE_PATH:/usr/include" 
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/lib:/usr/lib/x86_64-linux-gnu"
./configure --prefix=$(realpath "$SCRIPT_DIR"/opt) --disable-shared \
  LDFLAGS="--static" CFLAGS="-Os" CC=$CC

make -j $(nproc) 

cp -v .libs/libtelnet.a ..

popd
