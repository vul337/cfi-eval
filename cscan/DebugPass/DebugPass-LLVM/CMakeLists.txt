#cmake_minimum_required(VERSION 3.1)
cmake_minimum_required(VERSION 2.8)


find_package(LLVM REQUIRED CONFIG)
#add_definitions(${LLVM_DEFINITIONS})
#include_directories(${LLVM_INCLUDE_DIRS})
#link_directories(${LLVM_LIBRARY_DIRS})

add_subdirectory(src)  # Use your pass name here.

