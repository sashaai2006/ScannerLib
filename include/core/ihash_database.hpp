#pragma once

#include <optional>
#include <string_view>

class IHashDatabase {
 public:
  virtual ~IHashDatabase() = default;

  virtual std::optional<std::string_view> GetVerdict(
      std::string_view hash_hex) const = 0;
};
