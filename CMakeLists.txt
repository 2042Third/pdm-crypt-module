cmake_minimum_required(VERSION 3.18)
set (CMAKE_CXX_STANDARD 17)
project(cc20-ios )

enable_testing()

enable_language(CXX)
enable_language(OBJC)

MESSAGE( STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS} )
MESSAGE( STATUS "CMAKE_OBJC_FLAGS: " ${CMAKE_OBJC_FLAGS} )

if (PDM_TEST_PLATFORM_DESKTOP)
  MESSAGE( STATUS "Making PDM test platform for desktop." )
  set (PDM_TEST_PLATFORM DESKTOP) # Adds an executable, unset to build for mobile
endif()

set (PDM_BUILD_TYPE  MOBILE) # android
#set (PDM_BUILD_TYPE  MOBILE_IOS) # IOS
#set (PDM_BUILD_TYPE_MOBILE  ANDROID)# Uncomment to build for android

# Core source files
set(PDM_SOURCES ${PDM_SOURCES}
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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cc20_dev.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/cc20_dev.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cc20core/cc20_multi.cpp
    )

# includes
set(PDM_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/wasm
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp-mmf
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt
    )

# Header files
set(PDM_INCLUDE_FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/cc20_parts.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/cc20_multi.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/pdm-service.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/xCc20.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/cc20_diff.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/cc20_wrapper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/cc20_dev.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include/empp.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master/poly1305-donna-8.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master/poly1305-donna-16.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master/poly1305-donna.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master/poly1305-donna-64.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master/poly1305-donna-32.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cc20_file.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/nonwasm/endian.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp-mmf/memory_mapped_file.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/sha3.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/wasm/endian.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cc20_poly.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ec.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/test/test.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/include/scrypt.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/scrypt.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/sha256.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/pbkdf2.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/salsa20.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/common.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/src/hmac.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/fe25519.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/ecdh_curve25519.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/bigint.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/avrnacl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cc20_scrypt.h
    )

set(PDM_OPTIONS PUBLIC  LINUX ${PDM_OPTIONS})
set(PDM_COMPILER_FLAGS -g -lpthread -O3)
 if(${PDM_BUILD_TYPE} MATCHES MOBILE)

   MESSAGE( STATUS "Will run: MOBILE"  )
     project(cc20)
     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
     set(PDM_OPTIONS ${PDM_OPTIONS} ANDROID)
     if(${PDM_BUILD_TYPE_MOBILE} MATCHES ANDROID)
         set(PDM_INCLUDES ${PDM_INCLUDES} ../java/com/pdmnotes/)
         # Android bridge cpp file
         set(PDM_SOURCES "${PDM_SOURCES} ../java/com/pdmnotes/com_pdmnotes_PdmCrypt.c" src/cc20_dev.cpp src/include/cc20_dev.h src/cc20_dev.cpp)
     endif()

     add_library(cc20  ${PDM_SOURCES})
     target_compile_definitions(cc20 ${PDM_OPTIONS})
     target_compile_options(cc20 PUBLIC ${PDM_COMPILER_FLAGS})
     target_include_directories(cc20
         PUBLIC
         ${PDM_INCLUDES}
     )
 elseif(${PDM_BUILD_TYPE} MATCHES MOBILE_IOS)
    set(PDM_INCLUDE_FILES 
        ${PDM_INCLUDE_FILES}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/empp.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/emppIOS.h
    )
    set(PDM_SOURCES 
        ${PDM_SOURCES}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/emppIOS.mm
    )


    # Checks sanity
    include(CheckCXXSymbolExists)
    check_cxx_symbol_exists(kqueue sys/event.h HAVE_KQUEUE)
    if(NOT HAVE_KQUEUE)
      message(STATUS "kqueue NOT found!")
    else()
      message(STATUS "kqueue found!" )
    endif()

    find_library(APPKIT_LIBRARY AppKit)
    if (NOT APPKIT_LIBRARY)
      message(STATUS "AppKit.framework NOT found!")
    else()
      message(STATUS "AppKit.framework found! ${APPKIT_LIBRARY}")
    endif()

    find_library(FOUNDATION_LIBRARY Foundation)
    if (NOT FOUNDATION_LIBRARY)
      message(STATUS "Foundation.framework NOT found!")
    else()
      message(STATUS "Foundation.framework found! ${FOUNDATION_LIBRARY}")
    endif()

    find_library(UIKIT_LIBRARY UIKit)
    if (NOT UIKIT_LIBRARY)
      message(STATUS "UIKit.framework NOT found!")
    else()
      message(STATUS "UIKit.framework found! ${UIKIT_LIBRARY}")
    endif()

    # set(CMAKE_INSTALL_PREFIX ./libs)
    # Hook up XCTest for the supported plaforms (all but WatchOS)
    if(NOT PLATFORM MATCHES ".*WATCHOS.*")
      # Use the standard find_package, broken between 3.14.0 and 3.14.4 at least for XCtest...
      find_package(XCTest)
      # Fallback: Try to find XCtest as host package via toochain macro (should always work)
      find_host_package(XCTest REQUIRED)
    endif()

    # Includes
    include_directories(${PDM_INCLUDES})

    # include_directories(${cc20-app_SOURCE_DIR})

    # Make sure try_compile() works
    include(CheckTypeSize)
    check_type_size(time_t SIZEOF_TIME_T)

    # Source files
    set(SOURCES
      ${PDM_SOURCES}
    )

    # Headers
    set(HEADERS
      ${PDM_INCLUDE_FILES}
    )

    # Library
    if(BUILD_SHARED)
      add_library (cc20 SHARED ${SOURCES} ${HEADERS})
      target_link_libraries(cc20 ${FOUNDATION_LIBRARY})
      target_compile_definitions(cc20 PUBLIC IS_BUILDING_SHARED )
      message(STATUS "Building shared version...")
    else()
      add_library (cc20 STATIC ${SOURCES} ${HEADERS})
      target_link_libraries(cc20 ${FOUNDATION_LIBRARY})
      message(STATUS "Building static version...")
    endif()

    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
      set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/pdm-native-lib/libs CACHE PATH "Install path" FORCE)
    endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

    set(PDM_OPTIONS ${PDM_OPTIONS} ANDROID)
    target_compile_definitions(cc20 ${PDM_OPTIONS})
    target_compile_options(cc20 PUBLIC ${PDM_COMPILER_FLAGS})
    target_include_directories(cc20
        PUBLIC
        ${PDM_INCLUDES}
    )
    # Executable
    if(PLATFORM MATCHES "MAC.*")
      set(APP_NAME TestApp)
      add_executable (${APP_NAME} MACOSX_BUNDLE main.cpp)
      set_target_properties(${APP_NAME} PROPERTIES
              BUNDLE True
              MACOSX_BUNDLE_GUI_IDENTIFIER leetal.com.helloworld
              MACOSX_BUNDLE_BUNDLE_NAME helloworld
              MACOSX_BUNDLE_BUNDLE_VERSION "0.1"
              MACOSX_BUNDLE_SHORT_VERSION_STRING "0.1"
              )
      # Link the library with the executable
      target_link_libraries(${APP_NAME} example)
    endif()

    # Debug symbols set in XCode project
    set_xcode_property(cc20 GCC_GENERATE_DEBUGGING_SYMBOLS YES "All")

    # Installation
    if(PLATFORM MATCHES "MAC.*")
      install(TARGETS ${APP_NAME}
              BUNDLE DESTINATION . COMPONENT Runtime
              RUNTIME DESTINATION bin COMPONENT Runtime
              LIBRARY DESTINATION lib
              ARCHIVE DESTINATION lib/static)

      # Note Mac specific extension .app
      set(APPS "\${CMAKE_INSTALL_PREFIX}/${APP_NAME}.app")

      # Directories to look for dependencies
      set(DIRS ${CMAKE_BINARY_DIR})

      install(CODE "include(BundleUtilities)
        fixup_bundle(\"${APPS}\" \"\" \"${DIRS}\")")

      set(CPACK_GENERATOR "DRAGNDROP")
      include(CPack)
    else()
      install(TARGETS cc20
              LIBRARY DESTINATION ios/pdm-lib
              ARCHIVE DESTINATION ios/pdm-lib/static)
    endif()
    install (FILES ${HEADERS} DESTINATION include)

# DONE IOS
 else() # DESKTOP

#     LIBRARY COMPILE FINISH
MESSAGE( STATUS "Will run: DESKTOP"  )

     add_executable(cc20 src/desktop.cpp)

     target_compile_options(
         cc20 PUBLIC
         -g -lpthread -m64 -O3
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
     set(PDM_OPTIONS ${PDM_OPTIONS} )
     target_compile_definitions(cc20 PUBLIC WINDOWS LINUX HAS_MAIN ${PDM_OPTIONS})
     target_include_directories(cc20 PUBLIC
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
     target_link_libraries(cc20 c20_lib  c20_multi)
     #install(TARGETS cc20 )


 endif()
