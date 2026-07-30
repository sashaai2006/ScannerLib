find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(scanner_unit_tests
    unit/hash_base_test.cpp
    unit/hash_compute_test.cpp
    unit/block_queue_test.cpp
    unit/thread_pool_test.cpp
    unit/path_checker_test.cpp
)

target_link_libraries(scanner_unit_tests
    PRIVATE
        scanner_core
        GTest::gtest_main
)

add_executable(scanner_integration_tests
    integration/scanner_test.cpp
)

target_link_libraries(scanner_integration_tests
    PRIVATE
        scanner_core
        GTest::gtest_main
)

gtest_discover_tests(scanner_unit_tests)
gtest_discover_tests(scanner_integration_tests)
