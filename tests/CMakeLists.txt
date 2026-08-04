find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(scanner_unit_tests
    unit/hash_database_test.cpp
    unit/hash_compute_test.cpp
    unit/block_queue_test.cpp
    unit/thread_pool_test.cpp
    unit/path_validator_test.cpp
)

target_link_libraries(scanner_unit_tests
    PRIVATE
        scanner_core
        GTest::gtest_main
)

add_executable(scanner_integration_tests
    integration/scanner_test.cpp
    integration/batch_app_test.cpp
    ${CMAKE_SOURCE_DIR}/src/tui/batch_app.cpp
    ${CMAKE_SOURCE_DIR}/src/tui/cli_options.cpp
)

target_link_libraries(scanner_integration_tests
    PRIVATE
        scanner_core
        GTest::gtest_main
)

gtest_discover_tests(scanner_unit_tests)
gtest_discover_tests(scanner_integration_tests)
