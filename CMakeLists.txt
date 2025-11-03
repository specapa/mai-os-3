cmake_minimum_required(VERSION 3.10)

project(Lab1_SharedMemory C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -O2)

set(SYSTEM_LIBS pthread rt)

add_executable(parent src/parent.c)
target_link_libraries(parent ${SYSTEM_LIBS})

add_executable(child1 src/child1.c)
target_link_libraries(child1 ${SYSTEM_LIBS})

add_executable(child2 src/child2.c)
target_link_libraries(child2 ${SYSTEM_LIBS})
