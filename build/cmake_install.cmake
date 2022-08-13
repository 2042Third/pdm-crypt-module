# Install script for directory: /Users/mikeyang/Documents/pdm/pdm-crypt-module

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "../pdm-native-lib/libs")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Users/mikeyang/Downloads/Xcode-beta.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/objdump")
endif()

set(CMAKE_BINARY_DIR "/Users/mikeyang/Documents/pdm/pdm-crypt-module/build")

if(NOT PLATFORM_NAME)
  if(NOT "$ENV{PLATFORM_NAME}" STREQUAL "")
    set(PLATFORM_NAME "$ENV{PLATFORM_NAME}")
  endif()
  if(NOT PLATFORM_NAME)
    set(PLATFORM_NAME iphoneos)
  endif()
endif()

if(NOT EFFECTIVE_PLATFORM_NAME)
  if(NOT "$ENV{EFFECTIVE_PLATFORM_NAME}" STREQUAL "")
    set(EFFECTIVE_PLATFORM_NAME "$ENV{EFFECTIVE_PLATFORM_NAME}")
  endif()
  if(NOT EFFECTIVE_PLATFORM_NAME)
    set(EFFECTIVE_PLATFORM_NAME -iphoneos)
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static" TYPE STATIC_LIBRARY FILES "/Users/mikeyang/Documents/pdm/pdm-crypt-module/build/Debug${EFFECTIVE_PLATFORM_NAME}/libcc20.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
    endif()
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static" TYPE STATIC_LIBRARY FILES "/Users/mikeyang/Documents/pdm/pdm-crypt-module/build/Release${EFFECTIVE_PLATFORM_NAME}/libcc20.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
    endif()
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static" TYPE STATIC_LIBRARY FILES "/Users/mikeyang/Documents/pdm/pdm-crypt-module/build/MinSizeRel${EFFECTIVE_PLATFORM_NAME}/libcc20.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
    endif()
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static" TYPE STATIC_LIBRARY FILES "/Users/mikeyang/Documents/pdm/pdm-crypt-module/build/RelWithDebInfo${EFFECTIVE_PLATFORM_NAME}/libcc20.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/ios/pdm-lib/static/libcc20.a")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/cc20_parts.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/types.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/cc20_multi.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/pdm-service.hpp"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/xCc20.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/cc20_diff.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/cc20_wrapper.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/cc20_dev.hpp"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/include/empp.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/poly1305-donna-master/poly1305-donna-8.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/poly1305-donna-master/poly1305-donna-16.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/poly1305-donna-master/poly1305-donna.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/poly1305-donna-master/poly1305-donna-64.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/poly1305-donna-master/poly1305-donna-32.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/cc20_file.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/nonwasm/endian.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/cpp-mmf/memory_mapped_file.hpp"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/sha3.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/wasm/endian.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/cc20_poly.hpp"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/ec.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/test/test.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/include/scrypt.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/src/scrypt.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/src/sha256.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/src/pbkdf2.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/src/salsa20.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/src/common.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/scrypt/src/hmac.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/ecc/fe25519.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/ecc/ecdh_curve25519.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/ecc/bigint.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/ecc/avrnacl.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/lib/cc20_scrypt.h"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/empp.hpp"
    "/Users/mikeyang/Documents/pdm/pdm-crypt-module/src/emppIOS.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/mikeyang/Documents/pdm/pdm-crypt-module/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
