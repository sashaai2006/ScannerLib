#pragma once

#include <string_view>

class IPathValidator {
 public:
  virtual ~IPathValidator() = default;

  virtual void ValidateScanInputs(std::string_view csv_path,
                                  std::string_view log_path,
                                  std::string_view root_path) const = 0;

  virtual void ValidateScanTarget(std::string_view root_path) const = 0;
};
