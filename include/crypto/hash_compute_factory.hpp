#pragma once

#include "crypto/hash_compute.hpp"

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

class HashComputeFactory {
 public:
  using Creator = std::function<std::unique_ptr<IHashCompute>()>;

  static std::unique_ptr<IHashCompute> Create(std::string_view algorithm);

  static const std::vector<AlgorithmInfo>& AvailableAlgorithms() noexcept;
  static bool IsSupported(std::string_view algorithm) noexcept;
  static std::string CanonicalName(std::string_view algorithm);

 private:
  struct Entry {
    Creator creator;
    AlgorithmInfo info;
  };

  static const std::unordered_map<std::string, Entry>& Registry() noexcept;
};
