#pragma once

#include "core/ihash_source.hpp"
#include "utils/ilogger.hpp"

#include <string>
#include <string_view>

class CsvHashSource : public IHashSource {
 public:
  CsvHashSource(std::string_view csv_path, ILogger& logger);

  HashMap Load() override;

 private:
  static void Trim(std::string& value);

  std::string csv_path_;
  ILogger& logger_;
};
