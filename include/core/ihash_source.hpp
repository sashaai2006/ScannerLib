#pragma once

#include <string>
#include <unordered_map>

class IHashSource {
 public:
  using HashMap = std::unordered_map<std::string, std::string>;

  virtual ~IHashSource() = default;

  virtual HashMap Load() = 0;
};
