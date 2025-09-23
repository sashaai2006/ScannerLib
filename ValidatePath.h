#pragma once

#ifndef DLL_EXPORT
#  ifdef _WIN32
#    define DLL_EXPORT __declspec(dllexport)
#  else
#    define DLL_EXPORT
#  endif
#endif


#include <filesystem>
#include <system_error>
#include <fstream>
#include <stdexcept>
#include <string>

class DLL_EXPORT PathChecker {
public:
    static void validate_paths(const std::string& csv_path,
                              const std::string& log_path,
                              const std::string& root_path); 
    static bool is_valid_hash_base(const std::string& csv_path);
    static bool is_valid_log_path(const std::string& log_path);
    static bool is_valid_scan_directory(const std::string& root_path);
    static void ensure_log_directory_exists(const std::string& log_path);
};
