#include "crypto/md5_compute.hpp"

#include <openssl/md5.h>

std::optional<std::ifstream> MD5Compute::OpenFileForReading(
    const std::filesystem::path& file_path) const {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(file_path, ec) || ec) {
    return std::nullopt;
  }

  std::ifstream file(file_path, std::ios::binary);
  if (!file.is_open() || !file.good()) {
    return std::nullopt;
  }
  return file;
}

bool MD5Compute::ComputeMd5Digest(
    std::ifstream& file,
    unsigned char digest[MD5_DIGEST_LENGTH]) const {
  MD5_CTX ctx;
  if (MD5_Init(&ctx) != 1) {
    return false;
  }

  char buffer[BUFFER_SIZE];
  while (file.good()) {
    file.read(buffer, BUFFER_SIZE);
    const std::streamsize bytes_read = file.gcount();
    if (bytes_read > 0) {
      if (MD5_Update(&ctx, buffer, static_cast<size_t>(bytes_read)) != 1) {
        return false;
      }
    }
  }
  if (file.bad()) {
    return false;
  }

  if (MD5_Final(digest, &ctx) != 1) {
    return false;
  }

  return true;
}

std::string MD5Compute::DigestToHexString(
    const unsigned char digest[MD5_DIGEST_LENGTH]) noexcept {
  static constexpr char hex_chars[] = "0123456789abcdef";
  std::string result(MD5_DIGEST_LENGTH * 2, '\0');
  for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
    result[i * 2] = hex_chars[digest[i] >> 4];
    result[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
  }
  return result;
}

std::optional<std::string> MD5Compute::ComputeFileHashMD5(
    const std::filesystem::path& file_path) const {
  try {
    auto file_opt = OpenFileForReading(file_path);
    if (!file_opt.has_value()) {
      return std::nullopt;
    }

    unsigned char digest[MD5_DIGEST_LENGTH];
    if (!ComputeMd5Digest(file_opt.value(), digest)) {
      return std::nullopt;
    }
    return DigestToHexString(digest);

  } catch (const std::exception&) {
    return std::nullopt;
  }
}
