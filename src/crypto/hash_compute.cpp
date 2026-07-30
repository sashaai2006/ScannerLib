#include "crypto/hash_compute.hpp"

#include <openssl/evp.h>

#include <fstream>
#include <memory>
#include <vector>

HashComputeBase::HashComputeBase(std::string_view name,
                                 bool deprecated,
                                 const void* md)
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

                                                                         
                                               
  const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
      EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) {
    return std::nullopt;
  }

  if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
    return std::nullopt;
  }

  char buffer[kBufferSize];
  while (file.good()) {
    file.read(buffer, kBufferSize);
    const std::streamsize bytes_read = file.gcount();
    if (bytes_read > 0) {
      if (EVP_DigestUpdate(ctx.get(), buffer,
                           static_cast<size_t>(bytes_read)) != 1) {
        return std::nullopt;
      }
    }
  }

  if (file.bad()) {
    return std::nullopt;
  }

  std::vector<unsigned char> digest(digest_length_);
  unsigned int actual_length = 0;
  if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &actual_length) != 1) {
    return std::nullopt;
  }

  return DigestToHexString(digest.data(), actual_length);
}

std::string HashComputeBase::DigestToHexString(const unsigned char* digest,
                                               size_t length) {
  static constexpr char hex_chars[] = "0123456789abcdef";
  std::string result(length * 2, '\0');
  for (size_t i = 0; i < length; ++i) {
    result[i * 2] = hex_chars[digest[i] >> 4];
    result[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
  }
  return result;
}
