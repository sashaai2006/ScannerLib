#include "utils/logger.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <stdexcept>

Logger& Logger::Instance() {
  static Logger instance;
  return instance;
}

Logger::~Logger() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (file_.is_open()) {
    file_.flush();
    file_.close();
  }
}

void Logger::Init(const std::filesystem::path& log_path) {
  std::lock_guard<std::mutex> lock(mutex_);

  std::error_code ec;
  const std::filesystem::path log_dir = log_path.parent_path();
  if (!log_dir.empty() && !std::filesystem::exists(log_dir)) {
    std::filesystem::create_directories(log_dir, ec);
    if (ec) {
      throw std::runtime_error("Не удается создать директорию для лога: " +
                               log_dir.string() + " (" + ec.message() + ")");
    }
  }

  if (file_.is_open()) {
    file_.flush();
    file_.close();
  }

  file_.open(log_path, std::ios::out | std::ios::app);
  if (!file_.is_open()) {
    throw std::runtime_error("Не удается открыть файл лога: " +
                             log_path.string());
  }
}

void Logger::Log(Level level, std::string_view message) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!file_.is_open()) {
    return;
  }

  const auto now = std::chrono::system_clock::now();
  const auto time_t_now = std::chrono::system_clock::to_time_t(now);

  file_ << '['
        << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S")
        << "] [" << LevelToString(level) << "] " << message << '\n';
  file_.flush();
}

void Logger::Info(std::string_view message) {
  Log(Level::Info, message);
  std::cout << message << '\n';
}

void Logger::Warning(std::string_view message) {
  Log(Level::Warning, message);
  std::cerr << message << '\n';
}

void Logger::Error(std::string_view message) {
  Log(Level::Error, message);
  std::cerr << message << '\n';
}

std::string_view Logger::LevelToString(Level level) noexcept {
  switch (level) {
    case Level::Info:
      return "INFO";
    case Level::Warning:
      return "WARNING";
    case Level::Error:
      return "ERROR";
  }
  return "UNKNOWN";
}
