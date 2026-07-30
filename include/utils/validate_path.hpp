#pragma once

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>

class PathChecker {
 public:
  static void ValidatePaths(std::string_view csv_path,
                            std::string_view log_path,
                            std::string_view root_path);
  static bool IsValidHashBase(std::string_view csv_path);
  static bool IsValidLogPath(std::string_view log_path);
  static bool IsValidScanDirectory(std::string_view root_path);
  static void EnsureLogDirectoryExists(std::string_view log_path);
};
