#pragma once

#include "utils/ilogger.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>

class FileLogger : public ILogger {
 public:
  FileLogger() = default;
  explicit FileLogger(const std::filesystem::path& log_path);
  ~FileLogger() override;

  FileLogger(const FileLogger&) = delete;
  FileLogger& operator=(const FileLogger&) = delete;

  void Open(const std::filesystem::path& log_path);
  void Log(Level level, std::string_view message) override;

 private:
  static std::string_view LevelToString(Level level) noexcept;

  std::ofstream file_;
  std::mutex mutex_;
};
