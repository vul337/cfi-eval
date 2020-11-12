
#for c
clang -fuse-ld=lld -o libtest.so lib.c -shared -fPIC -flto
clang -fuse-ld=lld -o main main.c -L ./ -ltest -flto -fvisibility=hidden -ggdb -fno-sanitize-trap=all

#for c++
clang++ -fuse-ld=lld -o libtest.so lib.cpp -shared -fPIC -flto
clang++ -fuse-ld=lld -o main main.cpp -L ./ -ltest -flto -fvisibility=hidden -ggdb -fno-sanitize-trap=all
