#!/bin/bash

export CC=clang;
export CROSS_TOP=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer
export CROSS_SDK=iPhoneOS.sdk
export PATH="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin:$PATH"

# set -e

# export CURDIR=`pwd`

# export IOS_TOOLCHAIN_FILE=${CURDIR}/ios.toolchain.cmake

# export XCODE_VERSION_INT=13
# export INSTALL_DIR=$(pwd)/libs/ios

rm -rf build
mkdir build
cd build 

cmake .. -G Xcode  -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64COMBINED 
    # -DCMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM='Yang Yi' 
# cmake .. -G Xcode  -DENABLE_BITCODE=0  -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake \
#     -DPLATFORM=OS64COMBINED \
#     -DCMAKE_BUILD_TYPE=Debug \
#     -DCMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM='Yang Yi' 
chown -R mikeyang ./
cmake --build . --config Release
cmake --install . --config Release