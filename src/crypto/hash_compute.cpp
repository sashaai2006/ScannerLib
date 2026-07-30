#include "crypto/hash_compute.hpp"

#include <openssl/evp.h>

#include <fstream>
#include <stdexcept>
#include <vector>

namespace {

std::string ToUpper(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (char c : value) {
    result.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  }
  return result;
}

bool CaseInsensitiveEqual(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (size_t i = 0; i < lhs.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(lhs[i])) !=
        std::tolower(static_cast<unsigned char>(rhs[i]))) {
      return false;
    }
  }
  return true;
}

}  // namespace

HashCompute::HashCompute(std::string_view algorithm) {
  const std::string canonical = ToUpper(algorithm);

  const EVP_MD* md = nullptr;
  if (canonical == "MD5") {
    md = EVP_md5();
    deprecated_ = true;
  } else if (canonical == "SHA1") {
    md = EVP_sha1();
    deprecated_ = false;
  } else if (canonical == "SHA256") {
    md = EVP_sha256();
    deprecated_ = false;
  } else {
    throw std::invalid_argument("Неподдерживаемый алгоритм хеширования: " +
                                std::string(algorithm));
  }

  if (md == nullptr) {
    throw std::runtime_error("Не удалось инициализировать алгоритм: " +
                             canonical);
  }

  name_ = canonical;
  md_ = static_cast<const void*>(md);
  digest_length_ = static_cast<size_t>(EVP_MD_size(md));
}

std::optional<std::string> HashCompute::ComputeFileHash(
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

std::string HashCompute::DigestToHexString(const unsigned char* digest,
                                           size_t length) noexcept {
  static constexpr char hex_chars[] = "0123456789abcdef";
  std::string result(length * 2, '\0');
  for (size_t i = 0; i < length; ++i) {
    result[i * 2] = hex_chars[digest[i] >> 4];
    result[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
  }
  return result;
}

const std::vector<AlgorithmInfo>& HashCompute::AvailableAlgorithms() noexcept {
  static const std::vector<AlgorithmInfo> kAlgorithms = {
      {"MD5", true}, {"SHA1", false}, {"SHA256", false}};
  return kAlgorithms;
}

bool HashCompute::IsSupported(std::string_view algorithm) noexcept {
  for (const auto& info : AvailableAlgorithms()) {
    if (CaseInsensitiveEqual(info.name, algorithm)) {
      return true;
    }
  }
  return false;
}

std::string HashCompute::CanonicalName(std::string_view algorithm) {
  for (const auto& info : AvailableAlgorithms()) {
    if (CaseInsensitiveEqual(info.name, algorithm)) {
      return info.name;
    }
  }
  return std::string(algorithm);
}
