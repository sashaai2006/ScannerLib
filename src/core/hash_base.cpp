#include "core/hash_base.hpp"

#include "utils/logger.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string>

void HashBase::Trim(std::string& s) {
  const char* ws = " \t\r\n";
  const auto from = s.find_first_not_of(ws);
  if (from == std::string::npos) {
    s.clear();
    return;
  }
  const auto to = s.find_last_not_of(ws);
  s = s.substr(from, to - from + 1);
}

void HashBase::LoadHashes(std::string_view csv_path) {
  std::ifstream file{std::string(csv_path)};
  if (!file.is_open()) {
    throw std::runtime_error("Не удается открыть файл базы хешей: " +
                             std::string(csv_path));
  }
  std::string line;
  size_t line_num = 0;
  while (std::getline(file, line)) {
    ++line_num;
    Trim(line);

    if (line.empty()) {
      continue;
    }
    const auto pos = line.find(';');
    if (pos == std::string::npos) {
      continue;
    }
    std::string hash = line.substr(0, pos);
    std::string verdict = line.substr(pos + 1);
    Trim(hash);
    Trim(verdict);
    std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });

    if (hash.empty() || verdict.empty()) {
      Logger::Instance().Log(Logger::Level::Warning,
                             "Предупреждение: некорректная строка " +
                                 std::to_string(line_num) +
                                 " в базе хешей: " + line);
    } else {
      malicious_hashes_map_.emplace(std::move(hash), std::move(verdict));
    }
  }
}

const std::string* HashBase::GetVerdict(std::string_view hash_hex) const {
  const bool has_upper =
      std::any_of(hash_hex.begin(), hash_hex.end(),
                  [](unsigned char c) { return std::isupper(c) != 0; });

  if (!has_upper) {
    auto it = malicious_hashes_map_.find(hash_hex);
    return (it == malicious_hashes_map_.end()) ? nullptr : &it->second;
  }

  std::string hash_lower(hash_hex);
  std::transform(
      hash_lower.begin(), hash_lower.end(), hash_lower.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

  auto it = malicious_hashes_map_.find(hash_lower);
  return (it == malicious_hashes_map_.end()) ? nullptr : &it->second;
}
