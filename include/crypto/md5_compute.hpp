#pragma once

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

class MD5Compute {
 private:
  static constexpr size_t BUFFER_SIZE = 8192;
  static constexpr int MD5_DIGEST_LENGTH = 16;

 private:
  std::optional<std::ifstream> OpenFileForReading(
      const std::filesystem::path& file_path) const;
  bool ComputeMd5Digest(std::ifstream& file,
                        unsigned char digest[MD5_DIGEST_LENGTH]) const;
  static std::string DigestToHexString(
      const unsigned char digest[MD5_DIGEST_LENGTH]) noexcept;

 public:
  std::optional<std::string> ComputeFileHashMD5(
      const std::filesystem::path& file_path) const;
};
