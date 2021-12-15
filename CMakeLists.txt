add_library(cc20_multi
        include/cc20_multi.h
        clean_src/cc20_multi.cpp
        clean_src/cc20_dev.cpp
        clean_src/cc20_file.cpp
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