add_library(cc20_multi
        clean_src/cc20_multi.h
        clean_src/cc20_multi.cpp
        clean_src/cc20_dev.cpp
        clean_src/pdm-service.hpp
        lib/sha3.cpp
        lib/sha3.h
        lib/cpp-mmf/memory_mapped_file.cpp
        lib/poly1305-donna-master/poly1305-donna.c
        clean_src/cc20_parts.h)
target_compile_options(
        cc20_multi PUBLIC
        -pthread -m64
)
if(WIN32)
    target_compile_definitions(cc20_multi PUBLIC WINDOWS LINUX )
elseif (APPLE)
    target_compile_definitions(cc20_multi PUBLIC MACOS LINUX )
elseif (UNIX)
    target_compile_definitions(cc20_multi PUBLIC LINUX )
endif ()
#target_compile_definitions(cc20_multi PRIVATE LINUX )

target_include_directories(cc20_multi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/clean_src ${CMAKE_CURRENT_SOURCE_DIR}/lib)