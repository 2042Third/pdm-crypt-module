project(cc20_multi)
cmake_minimum_required(VERSION 3.0)
set (CMAKE_CXX_STANDARD 17)


if( ${PDM_BUILD_TYPE} MATCHES Library)
    message(STATUS "PDM-crypt-module library build ")
    add_library(cc20_multi
        include/cc20_multi.h
        src/cc20_multi.cpp
        src/cc20_file.cpp
        include/pdm-service.hpp
        lib/sha3.cpp
        lib/sha3.h
        lib/cpp-mmf/memory_mapped_file.cpp
        lib/poly1305-donna-master/poly1305-donna.cpp
        include/cc20_parts.h)
    target_compile_options(
        cc20_multi PUBLIC
        -pthread -m64 -D WINDOWS
    )
    if(WIN32)
        target_compile_definitions(cc20_multi PUBLIC WINDOWS LINUX DESKTOP_RELEASE )
    elseif (APPLE)
        target_compile_definitions(cc20_multi PUBLIC MACOS LINUX DESKTOP_RELEASE )
    elseif (UNIX)
        target_compile_definitions(cc20_multi PUBLIC LINUX DESKTOP_RELEASE )
    endif ()
    #target_compile_definitions(cc20_multi PRIVATE LINUX )

    target_include_directories(cc20_multi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/lib ${CMAKE_CURRENT_SOURCE_DIR}/lib/poly1305-donna-master/ )

elseif(${PDM_BUILD_TYPE} MATCHES Desktop)
    message(STATUS "PDM-crypt-module command-line executable build")
    add_executable(c20
        include/cc20_multi.h
        src/cc20_multi.cpp
        src/cc20_file.cpp
        include/pdm-service.hpp
        lib/sha3.cpp
        lib/sha3.h
        lib/cpp-mmf/memory_mapped_file.cpp
        lib/poly1305-donna-master/poly1305-donna.cpp
        include/cc20_parts.h
        lib/ecc/ecdh_curve25519.c
        lib/ecc/curve25519.c
        lib/ecc/fe25519.c
        lib/ecc/bigint.c
        src/ec.cpp
        )
    if(WIN32)
        target_compile_options(
            c20 PUBLIC
            -lpthread -m64 -O3
        )
        if(${PDM_BUILD_TYPE} MATCHES Four)
            set(PDM_OPTIONS ${PDM_OPTIONS} FOURCORE)
            message(STATUS "PDM build 4 cores ")
        elseif(${PDM_BUILD_TYPE} MATCHES Single)
            set(PDM_OPTIONS ${PDM_OPTIONS} SINGLETHREADING)
            message(STATUS "PDM build single-threaded ")
        else()
            message(STATUS "PDM build multi-thread (30 core)")
        endif()
        target_compile_definitions(c20 PUBLIC WINDOWS LINUX HAS_MAIN ${PDM_OPTIONS})
    elseif (APPLE)
        target_compile_definitions(c20 PUBLIC MACOS LINUX DESKTOP_RELEASE )
    elseif (UNIX)
        target_compile_options(
            c20 PUBLIC
            -lpthread -m64 -O3
        )
        target_compile_definitions(c20 PUBLIC LINUX HAS_MAIN )
    endif ()
    target_include_directories(c20 PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/poly1305-donna-master/
        lib/ecc/
        )

else()
    message(STATUS "PDM_BUILD_TYPE not defined; \"Library\" or \"Desktop\"")
endif()


