cmake_minimum_required(VERSION 3.20)

set(APP_SOURCES
    main.cpp
)

add_executable(scanner ${APP_SOURCES})

target_link_libraries(scanner
    PRIVATE
        scanner_core
)

target_include_directories(scanner
    PRIVATE
        ${CMAKE_SOURCE_DIR}/core
)

if(WIN32 AND MSVC)
    add_custom_command(TARGET scanner POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:scanner_core>
            $<TARGET_FILE_DIR:scanner>
        COMMENT "Copying scanner_core.dll to output directory"
    )
endif()

set_target_properties(scanner PROPERTIES
    OUTPUT_NAME "scanner"
    DEBUG_POSTFIX "_d"
)
