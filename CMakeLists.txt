cmake_minimum_required(VERSION 3.18)
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
project(c20 LANGUAGES CXX C)
cmake_policy(SET CMP0076 NEW)


# LIBRARY COMPILE FINISH

# WINDOWS
#add_executable(c20 src/desktop.cpp)
#target_compile_options(
#    c20 PUBLIC
#    -g -lpthread -m64 -O3
#)

# ANDROID
add_library(c20 SHARED src/empp.cpp)
find_library(fslib
    stdc++fs )



#target_compile_options(
#    c20
#    -g -lpthread -m64 -O3
#)

if(${PDM_BUILD_TYPE} MATCHES Four)
    set(PDM_OPTIONS ${PDM_OPTIONS} FOURCORE)
    message(STATUS "PDM build 4 cores ")
elseif(${PDM_BUILD_TYPE} MATCHES Single)
    set(PDM_OPTIONS ${PDM_OPTIONS} SINGLETHREADING)
    message(STATUS "PDM build single-threaded ")
else()
    message(STATUS "PDM build multi-thread (30 core)")
endif()
set(PDM_OPTIONS ${PDM_OPTIONS} )
target_compile_definitions(c20 PUBLIC LINUX  ${PDM_OPTIONS})
#target_compile_definitions(c20 PUBLIC WINDOWS LINUX HAS_MAIN ${PDM_OPTIONS})
target_include_directories(c20 PUBLIC
    src/include
    src/lib
    src/lib/cpp-mmf
    src/lib/poly1305-donna-master/
    src/lib/ecc/
    )

#
add_subdirectory(src/lib)
add_subdirectory(src/cc20core)
target_link_libraries(c20_multi c20_lib)
#other
#target_link_libraries(c20 c20_lib  c20_multi )
#android
target_link_libraries(c20 c20_lib  c20_multi ${fs-lib} )








