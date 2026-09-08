cmake_minimum_required(VERSION 3.18)
project(invalidsteamlogon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(invalidsteamlogon SHARED
    src/main.cpp
    src/scan.cpp
)

target_include_directories(invalidsteamlogon PRIVATE
    src/
    ${CMAKE_SOURCE_DIR}/third_party/funchook/include
)

target_link_libraries(invalidsteamlogon PRIVATE
    dl
    pthread
    X11
    ${CMAKE_SOURCE_DIR}/third_party/funchook/build/libfunchook.a
    ${CMAKE_SOURCE_DIR}/third_party/funchook/build/libdistorm.a
)

target_compile_options(invalidsteamlogon PRIVATE
    $<$<CONFIG:Release>:-O2 -fvisibility=hidden>
)

set_target_properties(invalidsteamlogon PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
