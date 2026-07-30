#include "crypto/hash_compute_factory.hpp"

#include "crypto/hash_algorithms.hpp"

#include <cctype>
#include <stdexcept>

namespace {

std::string ToUpper(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (char c : value) {
    result.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  }
  return result;
}

}             

std::unique_ptr<IHashCompute> HashComputeFactory::Create(
    std::string_view algorithm) {
  const std::string canonical = ToUpper(algorithm);
  const auto& registry = Registry();

  const auto it = registry.find(canonical);
  if (it == registry.end()) {
    throw std::invalid_argument("Неподдерживаемый алгоритм хеширования: " +
                                std::string(algorithm));
  }

  return it->second.creator();
}

const std::vector<AlgorithmInfo>& HashComputeFactory::AvailableAlgorithms()
    noexcept {
  static std::vector<AlgorithmInfo> algorithms = []() {
    const auto& registry = Registry();
    std::vector<AlgorithmInfo> result;
    result.reserve(registry.size());
    for (const auto& [name, entry] : registry) {
      result.push_back(entry.info);
    }
    return result;
  }();
  return algorithms;
}

bool HashComputeFactory::IsSupported(std::string_view algorithm) noexcept {
  const std::string canonical = ToUpper(algorithm);
  return Registry().find(canonical) != Registry().end();
}

std::string HashComputeFactory::CanonicalName(std::string_view algorithm) {
  const std::string canonical = ToUpper(algorithm);
  const auto& registry = Registry();
  const auto it = registry.find(canonical);
  if (it != registry.end()) {
    return it->second.info.name;
  }
  return std::string(algorithm);
}

const std::unordered_map<std::string, HashComputeFactory::Entry>&
HashComputeFactory::Registry() noexcept {
  static const std::unordered_map<std::string, Entry> registry = []() {
    std::unordered_map<std::string, Entry> result;

    auto add = [&result](auto creator, const AlgorithmInfo& info) {
      result.emplace(info.name, Entry{creator, info});
    };

    add([]() -> std::unique_ptr<IHashCompute> {
      return std::make_unique<Md5Compute>();
    }, AlgorithmInfo{"MD5", true});

    add([]() -> std::unique_ptr<IHashCompute> {
      return std::make_unique<Sha1Compute>();
    }, AlgorithmInfo{"SHA1", false});

    add([]() -> std::unique_ptr<IHashCompute> {
      return std::make_unique<Sha256Compute>();
    }, AlgorithmInfo{"SHA256", false});

    return result;
  }();
  return registry;
}
