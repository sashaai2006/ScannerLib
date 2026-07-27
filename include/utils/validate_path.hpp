#pragma once

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>

class PathChecker {
 public:
  static void ValidatePaths(const std::string& csv_path,
                            const std::string& log_path,
                            const std::string& root_path);
  static bool IsValidHashBase(const std::string& csv_path);
  static bool IsValidLogPath(const std::string& log_path);
  static bool IsValidScanDirectory(const std::string& root_path);
  static void EnsureLogDirectoryExists(const std::string& log_path);
};
