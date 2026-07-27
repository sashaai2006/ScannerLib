cmake_minimum_required(VERSION 3.20)
project(ScannerLib VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# macOS/Homebrew hint (на Linux OpenSSL находится из системных пакетов)
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH
        "/opt/homebrew/opt/openssl"
        "/usr/local/opt/openssl"
        "/opt/homebrew/opt/googletest"
        "/usr/local/opt/googletest"
    )
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(scanner_core STATIC
    src/core/scanner.cpp
    src/core/hash_base.cpp
    src/crypto/md5_compute.cpp
    src/utils/logger.cpp
    src/utils/validate_path.cpp
)

target_include_directories(scanner_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(scanner_core
    PUBLIC
        OpenSSL::Crypto
        Threads::Threads
)

if(MSVC)
    target_compile_options(scanner_core PRIVATE /W4)
else()
    target_compile_options(scanner_core PRIVATE -Wall -Wextra)
endif()

add_executable(scanner src/main.cpp)

target_link_libraries(scanner
    PRIVATE
        scanner_core
)

set_target_properties(scanner PROPERTIES
    OUTPUT_NAME "scanner"
    DEBUG_POSTFIX "_d"
)

option(SCANNER_BUILD_TESTS "Build tests" ON)
if(SCANNER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
