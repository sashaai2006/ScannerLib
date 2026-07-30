#include "core/hash_database.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

HashDatabase::HashDatabase(std::unordered_map<std::string, std::string> hashes)
    : malicious_hashes_map_(std::make_move_iterator(hashes.begin()),
                            std::make_move_iterator(hashes.end())) {}

std::optional<std::string_view> HashDatabase::GetVerdict(
    std::string_view hash_hex) const {
  const bool has_upper =
      std::any_of(hash_hex.begin(), hash_hex.end(),
                  [](unsigned char c) { return std::isupper(c) != 0; });

  if (!has_upper) {
    const auto it = malicious_hashes_map_.find(hash_hex);
    if (it == malicious_hashes_map_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  std::string hash_lower(hash_hex);
  std::transform(
      hash_lower.begin(), hash_lower.end(), hash_lower.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

  const auto it = malicious_hashes_map_.find(hash_lower);
  if (it == malicious_hashes_map_.end()) {
    return std::nullopt;
  }
  return it->second;
}
