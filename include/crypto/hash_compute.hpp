#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

class IHashCompute {
 public:
  virtual ~IHashCompute() = default;

  virtual std::optional<std::string> ComputeFileHash(
      const std::filesystem::path& file_path) const = 0;
  virtual std::string_view AlgorithmName() const noexcept = 0;
  virtual bool IsDeprecated() const noexcept = 0;
};

struct AlgorithmInfo {
  std::string name;
  bool deprecated;
};

class HashComputeBase : public IHashCompute {
 protected:
  HashComputeBase(std::string_view name,
                  bool deprecated,
                  const void* md);

 public:
  std::optional<std::string> ComputeFileHash(
      const std::filesystem::path& file_path) const override;
  std::string_view AlgorithmName() const noexcept override { return name_; }
  bool IsDeprecated() const noexcept override { return deprecated_; }

 protected:
  virtual ~HashComputeBase() = default;

 private:
  static constexpr size_t kBufferSize = 8192;

  std::string name_;
  bool deprecated_;
  const void* md_;
  size_t digest_length_;

  static std::string DigestToHexString(const unsigned char* digest,
                                       size_t length);
};
