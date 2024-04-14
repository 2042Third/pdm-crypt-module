cmake_minimum_required(VERSION 3.18)
project(cc20)

set(CMAKE_CXX_STANDARD 17)

option(WEB_RELEASE_LINUX_TEST "Build desktop debug version" ON)

option(BUILD_SHARED "Build shared library" OFF)
option(BUILD_DESKTOP "Build desktop version" ON)
option(BUILD_IOS "Build iOS version" OFF)
option(BUILD_ANDROID "Build Android version" OFF)

set(PDM_SOURCES
    src/cc20_dev.cpp
    src/lib/cc20_file.cpp
    src/lib/sha3.cpp
    src/lib/cpp-mmf/memory_mapped_file.cpp
    src/lib/poly1305-donna-master/poly1305-donna.cpp
    src/lib/ecc/ecdh_curve25519.c
    src/lib/ecc/curve25519.c
    src/lib/ecc/fe25519.c
    src/lib/ecc/bigint.c
    src/lib/scrypt/src/hmac.c
    src/lib/scrypt/src/pbkdf2.c
    src/lib/scrypt/src/salsa20.c
    src/lib/scrypt/src/scrypt.c
    src/empp.cpp
    src/lib/scrypt/src/sha256.c
    src/lib/ec.cpp
    src/cc20core/cc20_multi.cpp
    src/lib/misc/base64.cpp
    src/lib/misc/md5.cpp
)

set(PDM_INCLUDES
    src/include
    src/lib
    src/lib/wasm
    src/lib/cpp-mmf
    src/lib/poly1305-donna-master
    src/lib/ecc
    src/lib/scrypt/include
    src/lib/scrypt
)

set(PDM_HEADERS
    src/include/cc20_parts.h
    src/include/types.h
    src/include/cc20_multi.h
    src/include/pdm-service.hpp
    src/include/xCc20.h
    src/include/cc20_diff.h
    src/include/cc20_wrapper.h
    src/include/cc20_dev.h
    src/include/empp.h
    src/lib/crypto_rand.hpp
    src/lib/poly1305-donna-master/poly1305-donna-8.h
    src/lib/poly1305-donna-master/poly1305-donna-16.h
    src/lib/poly1305-donna-master/poly1305-donna.h
    src/lib/poly1305-donna-master/poly1305-donna-64.h
    src/lib/poly1305-donna-master/poly1305-donna-32.h
    src/lib/cc20_file.h
    src/lib/nonwasm/endian.h
    src/lib/cpp-mmf/memory_mapped_file.hpp
    src/lib/sha3.h
    src/lib/misc/md5.h
    src/lib/wasm/endian.h
    src/lib/cc20_poly.hpp
    src/lib/ec.h
    src/lib/scrypt/test/test.h
    src/lib/scrypt/include/scrypt.h
    src/lib/scrypt/src/scrypt.h
    src/lib/scrypt/src/sha256.h
    src/lib/scrypt/src/pbkdf2.h
    src/lib/scrypt/src/salsa20.h
    src/lib/scrypt/src/common.h
    src/lib/scrypt/src/hmac.h
    src/lib/ecc/fe25519.h
    src/lib/ecc/ecdh_curve25519.h
    src/lib/ecc/bigint.h
    src/lib/ecc/avrnacl.h
    src/lib/cc20_scrypt.h
    src/lib/misc/base64.h
)

add_library(cc20 ""
    src/kyber/ntt.cpp
    src/kyber/ntt.h)

target_sources(cc20 PRIVATE ${PDM_SOURCES})
target_include_directories(cc20 PUBLIC ${PDM_INCLUDES})

if(BUILD_SHARED)
  target_compile_definitions(cc20 PUBLIC IS_BUILDING_SHARED)
  set_target_properties(cc20 PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

if(BUILD_DESKTOP)

  target_sources(cc20 PRIVATE src/desktop.cpp)
  target_compile_definitions(cc20 PUBLIC WINDOWS LINUX HAS_MAIN)
  if(WEB_RELEASE_LINUX_TEST)
    target_compile_definitions(cc20 PUBLIC WEB_RELEASE_LINUX_TEST)
  endif()
  target_compile_options(cc20 PUBLIC -g -lpthread -m64 -O3)

  option(BUILD_FOURCORE "Build with 4 cores" OFF)
  option(BUILD_SINGLETHREADED "Build single-threaded" OFF)

  if(BUILD_FOURCORE)
    target_compile_definitions(cc20 PUBLIC FOURCORE)
  elseif(BUILD_SINGLETHREADED)
    target_compile_definitions(cc20 PUBLIC SINGLETHREADING)
  endif()


  add_executable(cc20_desktop src/desktop.cpp)
  target_link_libraries(cc20_desktop cc20)

elseif(BUILD_IOS)
  enable_language(OBJC)

  find_library(FOUNDATION_LIBRARY Foundation REQUIRED)

  target_sources(cc20 PRIVATE
      src/emppIOS.mm
      src/lib/crypto_rand.hpp
  )

  target_include_directories(cc20 PUBLIC
      src/empp.hpp
      src/emppIOS.h
  )

  target_link_libraries(cc20 PUBLIC ${FOUNDATION_LIBRARY})
  target_compile_definitions(cc20 PUBLIC ANDROID)

  set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/pdm-native-lib/libs CACHE PATH "Install path" FORCE)

  install(TARGETS cc20
      LIBRARY DESTINATION ios/pdm-lib
      ARCHIVE DESTINATION ios/pdm-lib/static
  )
  install(FILES ${PDM_HEADERS} DESTINATION include)

elseif(BUILD_ANDROID)
  target_sources(cc20 PRIVATE ../java/com/pdmnotes/com_pdmnotes_PdmCrypt.c)
  target_include_directories(cc20 PUBLIC ../java/com/pdmnotes/)
  target_compile_definitions(cc20 PUBLIC ANDROID)
endif()

target_compile_features(cc20 PUBLIC cxx_std_17)