#pragma once

#include <cstddef>
#include <optional>
#include <string>

struct CliOptions {
  std::string base_path;
  std::string log_path;
  std::string scan_path;
  std::string threads = "4";
  std::string algorithm = "SHA256";
  bool batch = false;
  std::string report_path;

  static std::optional<CliOptions> Parse(int argc, char* argv[]);

  static size_t ParseThreadCount(const std::string& value);

  static std::string Usage(const char* program_name);
};
