#pragma once

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string_view>

class Logger {
 public:
  enum class Level { Info, Warning, Error };

  static Logger& Instance();

  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  void Init(const std::filesystem::path& log_path);

  void Log(Level level, std::string_view message);

  void Info(std::string_view message);
  void Warning(std::string_view message);
  void Error(std::string_view message);

 private:
  Logger() = default;
  ~Logger();

  static std::string_view LevelToString(Level level) noexcept;

  std::ofstream file_;
  std::mutex mutex_;
};
