#!/bin/bash

export CC=clang;
export CROSS_TOP=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer
export CROSS_SDK=iPhoneOS.sdk
export PATH="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin:$PATH"

set -e

export CURDIR=`pwd`

export IOS_TOOLCHAIN_FILE=${CURDIR}/ios.toolchain.cmake

export XCODE_VERSION_INT=13
export INSTALL_DIR=$(pwd)/libs/ios
rm -rf build
mkdir build
cd build 

# cmake .. -G Xcode  -DENABLE_BITCODE=0  -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64 \
#   -DCMAKE_BUILD_TYPE=Debug \
#   -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR ../ \
#   -DCMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM='Yang Yi'
cmake .. -G Xcode  -DENABLE_BITCODE=0  -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64COMBINED \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM='Yang Yi' \
  -DBUILD_SHARED=FALSE \
  -DXCODE_VERSION=14 \
  -DENABLE_VISIBILITY=TRUE 
chown -R mikeyang ./
cmake --build . --config Debug 
# cmake --build . --config Release
# cmake --install . --config Release