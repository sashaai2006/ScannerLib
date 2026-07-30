#pragma once

#include <cctype>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

class HashCompute : public IHashCompute {
 private:
  static constexpr size_t kBufferSize = 8192;

  std::string name_;
  bool deprecated_;
  const void* md_;
  size_t digest_length_;

 private:
  static std::string DigestToHexString(const unsigned char* digest,
                                       size_t length) noexcept;

 public:
  explicit HashCompute(std::string_view algorithm);

  std::optional<std::string> ComputeFileHash(
      const std::filesystem::path& file_path) const override;
  std::string_view AlgorithmName() const noexcept override { return name_; }
  bool IsDeprecated() const noexcept override { return deprecated_; }

  static const std::vector<AlgorithmInfo>& AvailableAlgorithms() noexcept;
  static bool IsSupported(std::string_view algorithm) noexcept;
  static std::string CanonicalName(std::string_view algorithm);
};
