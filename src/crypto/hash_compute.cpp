#include "crypto/hash_compute.hpp"

#include <openssl/evp.h>

#include <fstream>
#include <vector>

HashComputeBase::HashComputeBase(std::string_view name,
                                 bool deprecated,
                                 const void* md) noexcept
    : name_(name),
      deprecated_(deprecated),
      md_(md),
      digest_length_(
          static_cast<size_t>(EVP_MD_size(static_cast<const EVP_MD*>(md)))) {}

std::optional<std::string> HashComputeBase::ComputeFileHash(
    const std::filesystem::path& file_path) const {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(file_path, ec) || ec) {
    return std::nullopt;
  }

  std::ifstream file(file_path, std::ios::binary);
  if (!file.is_open() || !file.good()) {
    return std::nullopt;
  }

  const EVP_MD* md = static_cast<const EVP_MD*>(md_);

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return std::nullopt;
  }

  if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    return std::nullopt;
  }

  char buffer[kBufferSize];
  while (file.good()) {
    file.read(buffer, kBufferSize);
    const std::streamsize bytes_read = file.gcount();
    if (bytes_read > 0) {
      if (EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(bytes_read)) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::nullopt;
      }
    }
  }

  if (file.bad()) {
    EVP_MD_CTX_free(ctx);
    return std::nullopt;
  }

  std::vector<unsigned char> digest(digest_length_);
  unsigned int actual_length = 0;
  if (EVP_DigestFinal_ex(ctx, digest.data(), &actual_length) != 1) {
    EVP_MD_CTX_free(ctx);
    return std::nullopt;
  }
  EVP_MD_CTX_free(ctx);

  return DigestToHexString(digest.data(), actual_length);
}

std::string HashComputeBase::DigestToHexString(const unsigned char* digest,
                                               size_t length) noexcept {
  static constexpr char hex_chars[] = "0123456789abcdef";
  std::string result(length * 2, '\0');
  for (size_t i = 0; i < length; ++i) {
    result[i * 2] = hex_chars[digest[i] >> 4];
    result[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
  }
  return result;
}
