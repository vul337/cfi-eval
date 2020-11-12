#!/bin/bash
rm -rf build
mkdir build
cd build
cmake ..
make -j
#/usr/local/bin/clang -Xclang -load -Xclang ~/Tsinghua_phd/CFI/DebugPass/build/src/libDebug.so -c -emit-llvm -DSPEC_CPU -DNDEBUG    -O2 -g       -DSPEC_CPU_LP64         /home/dora/install_spec2006/benchspec/CPU2006/401.bzip2/build/build_base_gcc41-64bit.0000/decompress.c
#llvm-dis ./decompress.bc
