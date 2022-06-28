cmake_minimum_required(VERSION 3.19)

cmake_policy(SET CMP0076 NEW)
add_library(xcc20 SHARED
    xCc20.cpp
    )
target_include_directories(xcc20 PUBLIC
    ../include
    ./
    ../lib/
    ../lib/cpp-mmf
    ../lib/poly1305-donna-master/
    ../lib/ecc/
    )
target_compile_options(
    xcc20 PUBLIC
    -g -lpthread -m64 -O3
)
set(PDM_OPTIONS ${PDM_OPTIONS} VERBOSE)
target_compile_definitions(xcc20 PUBLIC WINDOWS LINUX HAS_MAIN PRINTING DEEP_DEBUG ${PDM_OPTIONS})
#install(FILES libxcc20.dll DESTINATION ../../)