#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

class HashBase {
 private:
  struct TransparentHash {
    using is_transparent = void;
    size_t operator()(std::string_view value) const noexcept {
      return std::hash<std::string_view>{}(value);
    }
  };

  std::unordered_map<std::string, std::string, TransparentHash, std::equal_to<>>
      malicious_hashes_map_;

 private:
  static void Trim(std::string& s);

 public:
  void LoadHashes(std::string_view csv_path);
  const std::string* GetVerdict(std::string_view hash_hex) const;
};
