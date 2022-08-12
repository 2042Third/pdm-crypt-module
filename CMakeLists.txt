cmake_minimum_required(VERSION 3.18)
# set (CMAKE_CXX_STANDARD 17)
project(pdm-crypt-module )

enable_testing()

enable_language(CXX)
enable_language(OBJC)
MESSAGE( STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS} )
MESSAGE( STATUS "CMAKE_OBJC_FLAGS: " ${CMAKE_OBJC_FLAGS} )

cmake_policy(SET CMP0076 NEW)



# set (PDM_BUILD_TYPE  MOBILE)
set (PDM_BUILD_TYPE  MOBILE_IOS) # IOS
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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt)

set(PDM_OPTIONS PUBLIC  LINUX ${PDM_OPTIONS})
set(PDM_COMPILER_FLAGS -g -lpthread -O3)
if(${PDM_BUILD_TYPE} MATCHES MOBILE)
    project(c20)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
    set(PDM_OPTIONS ${PDM_OPTIONS} ANDROID)
    if(${PDM_BUILD_TYPE_MOBILE} MATCHES ANDROID)
        set(PDM_INCLUDES ${PDM_INCLUDES} ../java/com/pdmnotes/)
        # Android bridge cpp file
        set(PDM_SOURCES "${PDM_SOURCES} ../java/com/pdmnotes/com_pdmnotes_PdmCrypt.c" )
    endif()

    add_library(${PROJECT_NAME} SHARED ${PDM_SOURCES})
    target_compile_definitions(${PROJECT_NAME} ${PDM_OPTIONS})
    target_compile_options(c20 PUBLIC ${PDM_COMPILER_FLAGS})
    target_include_directories(${PROJECT_NAME}
        PUBLIC
        ${PDM_INCLUDES}
    )
elseif(${PDM_BUILD_TYPE} MATCHES MOBILE_IOS)
    # Checks sanity
    include(CheckCXXSymbolExists)
    check_cxx_symbol_exists(kqueue sys/event.h HAVE_KQUEUE)
    if(NOT HAVE_KQUEUE)
      message(STATUS "kqueue NOT found!")
    else()
      message(STATUS "kqueue found!")
    endif()

    # Hook up XCTest for the supported plaforms (all but WatchOS)
    if(NOT PLATFORM MATCHES ".*WATCHOS.*")
      # Use the standard find_package, broken between 3.14.0 and 3.14.4 at least for XCtest...
      find_package(XCTest)
      # Fallback: Try to find XCtest as host package via toochain macro (should always work)
      find_host_package(XCTest REQUIRED)
    endif()

    # Includes
    include_directories(${pdm-crypt-module_SOURCE_DIR} ${PDM_INCLUDES})
    # Make sure try_compile() works
    include(CheckTypeSize)
    check_type_size(time_t SIZEOF_TIME_T)
    # Source files
    set(SOURCES
      ${PDM_SOURCES}
    )

    # Headers
    set(HEADERS
      ${CMAKE_CURRENT_SOURCE_DIR}/src/include/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/cpp-mmf/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/poly1305-donna-master/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/ecc/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/include/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib/scrypt/*.h
    )

    # Library
    if(BUILD_SHARED)
      add_library (c20 SHARED ${SOURCES} ${HEADERS})
      target_link_libraries(c20 ${FOUNDATION_LIBRARY})
      target_compile_definitions(c20 PUBLIC IS_BUILDING_SHARED)
      message(STATUS "Building shared version...")
    else()
      add_library (c20 STATIC ${SOURCES} ${HEADERS})
      target_link_libraries(c20 ${FOUNDATION_LIBRARY})
      message(STATUS "Building static version...")
    endif()

    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
      set(CMAKE_INSTALL_PREFIX ${pdm-crypt-module_SOURCE_DIR}/../build-pdm-crypt-module/pdm-lib CACHE PATH "Install path" FORCE)
    endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

    set(PDM_OPTIONS ${PDM_OPTIONS} ANDROID)
    target_compile_definitions(${PROJECT_NAME} ${PDM_OPTIONS})
    target_compile_options(c20 PUBLIC ${PDM_COMPILER_FLAGS})
    target_include_directories(${PROJECT_NAME}
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
    set_xcode_property(c20 GCC_GENERATE_DEBUGGING_SYMBOLS YES "All")

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
      install(TARGETS c20
              LIBRARY DESTINATION lib
              ARCHIVE DESTINATION lib/static)
    endif()
    install (FILES ${HEADERS} DESTINATION include)

# DONE IOS
else() # DESKTOP

    # LIBRARY COMPILE FINISH

    add_executable(c20 src/desktop.cpp)

    target_compile_options(
        c20 PUBLIC
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
    target_compile_definitions(c20 PUBLIC WINDOWS LINUX HAS_MAIN ${PDM_OPTIONS})
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
    target_link_libraries(c20 c20_lib  c20_multi)
    #install(TARGETS c20 )


endif()
