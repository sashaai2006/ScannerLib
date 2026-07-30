#pragma once

#include "utils/ipath_validator.hpp"

class PathValidator : public IPathValidator {
 public:
  void ValidateScanInputs(std::string_view csv_path,
                          std::string_view log_path,
                          std::string_view root_path) const override;

  void ValidateScanTarget(std::string_view root_path) const override;

 private:
  static void ValidateCsvPath(std::string_view csv_path);
  static void ValidateLogPath(std::string_view log_path);
  static void ValidateRootPath(std::string_view root_path);
};
