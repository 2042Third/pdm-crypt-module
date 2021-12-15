add_library(cc20_multi
        includes/cc20_multi.h
        clean_src/cc20_multi.cpp
        clean_src/cc20_dev.cpp
        includes/pdm-service.hpp
        lib/sha3.cpp
        lib/sha3.h
        lib/cpp-mmf/memory_mapped_file.cpp
        lib/poly1305-donna-master/poly1305-donna.c
        includes/cc20_parts.h)
target_compile_options(
        cc20_multi PUBLIC
        -pthread -m64 -D WINDOWS
)
if(WIN32)
    target_compile_definitions(cc20_multi PUBLIC WINDOWS LINUX )
elseif (APPLE)
    target_compile_definitions(cc20_multi PUBLIC MACOS LINUX )
elseif (UNIX)
    target_compile_definitions(cc20_multi PUBLIC LINUX )
endif ()
#target_compile_definitions(cc20_multi PRIVATE LINUX )

target_include_directories(cc20_multi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/includes ${CMAKE_CURRENT_SOURCE_DIR}/lib)