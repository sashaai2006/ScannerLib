#pragma once

#include <string_view>

class ILogger {
 public:
  enum class Level { Info, Warning, Error };

  virtual ~ILogger() = default;

  virtual void Log(Level level, std::string_view message) = 0;
};
