#pragma once

#include "core/ihash_database.hpp"

#include <functional>
#include <string>
#include <unordered_map>

class HashDatabase : public IHashDatabase {
 public:
  explicit HashDatabase(std::unordered_map<std::string, std::string> hashes);

  std::optional<std::string_view> GetVerdict(
      std::string_view hash_hex) const override;

 private:
  struct TransparentHash {
    using is_transparent = void;
    size_t operator()(std::string_view value) const noexcept {
      return std::hash<std::string_view>{}(value);
    }
  };

  std::unordered_map<std::string, std::string, TransparentHash, std::equal_to<>>
      malicious_hashes_map_;
};
