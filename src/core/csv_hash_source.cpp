#include "core/csv_hash_source.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <utility>

CsvHashSource::CsvHashSource(std::string_view csv_path, ILogger& logger)
    : csv_path_(csv_path), logger_(logger) {}

void CsvHashSource::Trim(std::string& value) {
  const char* whitespace = " \t\r\n";
  const auto first = value.find_first_not_of(whitespace);
  if (first == std::string::npos) {
    value.clear();
    return;
  }
  const auto last = value.find_last_not_of(whitespace);
  value = value.substr(first, last - first + 1);
}

CsvHashSource::HashMap CsvHashSource::Load() {
  std::ifstream file{csv_path_};
  if (!file.is_open()) {
    throw std::runtime_error("Не удается открыть файл базы хешей: " + csv_path_);
  }

  HashMap result;
  std::string line;
  size_t line_number = 0;
  while (std::getline(file, line)) {
    ++line_number;
    Trim(line);

    if (line.empty()) {
      continue;
    }

    const auto separator_pos = line.find(';');
    if (separator_pos == std::string::npos) {
      continue;
    }

    std::string hash = line.substr(0, separator_pos);
    std::string verdict = line.substr(separator_pos + 1);
    Trim(hash);
    Trim(verdict);
    std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });

    if (hash.empty() || verdict.empty()) {
      logger_.Log(ILogger::Level::Warning,
                  "Предупреждение: некорректная строка " +
                      std::to_string(line_number) + " в базе хешей: " + line);
    } else {
      result.emplace(std::move(hash), std::move(verdict));
    }
  }

  return result;
}
