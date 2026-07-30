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
        "/opt/homebrew/opt/ftxui"
        "/usr/local/opt/ftxui"
    )
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(ftxui CONFIG QUIET)

if(NOT ftxui_FOUND)
    include(FetchContent)
    FetchContent_Declare(ftxui
        URL https://github.com/ArthurSonzogni/FTXUI/archive/refs/tags/v7.0.1.tar.gz)
    FetchContent_MakeAvailable(ftxui)
endif()

add_library(scanner_core STATIC
    src/core/scanner.cpp
    src/core/csv_hash_source.cpp
    src/core/hash_database.cpp
    src/core/directory_walker.cpp
    src/core/scan_controller.cpp
    src/crypto/hash_compute.cpp
    src/crypto/hash_algorithms.cpp
    src/crypto/hash_compute_factory.cpp
    src/threading/thread_pool.cpp
    src/utils/file_logger.cpp
    src/utils/path_validator.cpp
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

add_executable(scannerlib
    src/main.cpp
    src/tui/tui_app.cpp
    src/tui/cli_options.cpp
)

target_link_libraries(scannerlib
    PRIVATE
        scanner_core
        ftxui::component
        ftxui::dom
        ftxui::screen
)

set_target_properties(scannerlib PROPERTIES
    OUTPUT_NAME "scannerlib"
)

install(TARGETS scannerlib DESTINATION bin)

option(SCANNER_BUILD_TESTS "Build tests" ON)
if(SCANNER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
