cmake_minimum_required(VERSION 3.18)
set (CMAKE_CXX_STANDARD 17)
project(c20 LANGUAGES CXX C)
cmake_policy(SET CMP0076 NEW)

set (PDM_BUILD_TYPE  ANDROID)

if(${PDM_BUILD_TYPE} MATCHES ANDROID)
    project(c20)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")


    add_library(
        ${PROJECT_NAME}
        SHARED
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cc20_file.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/sha3.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp-mmf/memory_mapped_file.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master/poly1305-donna.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/ecdh_curve25519.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/curve25519.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/fe25519.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/bigint.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/hmac.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/pbkdf2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/salsa20.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/scrypt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/empp.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/sha256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ec.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cc20_poly.hpp
        ../java/com/pdmnotes/com_pdmnotes_PdmCrypt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cc20core/cc20_multi.cpp
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/wasm
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp-mmf
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/include
#        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt
    )
    target_compile_definitions(c20 PUBLIC ANDROID LINUX ${PDM_OPTIONS})
    target_compile_options(
        c20 PUBLIC
        -g -lpthread -m64 -O3
        -DTARGET_ARCH=ANDROID
        --arch
    )
    target_include_directories(
        ${PROJECT_NAME}
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/wasm
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp-mmf
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt
    )
else()

## LIBRARY COMPILE FINISH
#
#add_executable(c20 src/desktop.cpp)
#
#target_compile_options(
#    c20 PUBLIC
#    -g -lpthread -m64 -O3
#)
#
#if(${PDM_BUILD_TYPE} MATCHES Four)
#    set(PDM_OPTIONS ${PDM_OPTIONS} FOURCORE)
#    message(STATUS "PDM build 4 cores ")
#elseif(${PDM_BUILD_TYPE} MATCHES Single)
#    set(PDM_OPTIONS ${PDM_OPTIONS} SINGLETHREADING)
#    message(STATUS "PDM build single-threaded ")
#else()
#    message(STATUS "PDM build multi-thread (30 core)")
#endif()
#set(PDM_OPTIONS ${PDM_OPTIONS} )
#target_compile_definitions(c20 PUBLIC WINDOWS LINUX HAS_MAIN ${PDM_OPTIONS})
#target_include_directories(c20 PUBLIC
#    src/include
#    src/lib
#    src/lib/cpp-mmf
#    src/lib/poly1305-donna-master/
#    src/lib/ecc/
#    )
##
#add_subdirectory(src/lib)
#add_subdirectory(src/cc20core)
#target_link_libraries(c20_multi c20_lib)
#target_link_libraries(c20 c20_lib  c20_multi)
##install(TARGETS c20 )


endif()
