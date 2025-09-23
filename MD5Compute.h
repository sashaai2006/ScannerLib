#pragma once

#ifndef DLL_EXPORT
#  ifdef _WIN32
#    define DLL_EXPORT __declspec(dllexport)
#  else
#    define DLL_EXPORT
#  endif
#endif

#include <filesystem>
#include <optional>
#include <string>
#include <fstream>

class DLL_EXPORT MD5Compute {
private:
    static constexpr size_t BUFFER_SIZE = 8192;
    static constexpr int MD5_DIGEST_LENGTH = 16;
private:
    std::optional<std::ifstream> open_file_for_reading(const std::filesystem::path& file_path) const;
    bool compute_md5_digest(std::ifstream& file, unsigned char digest[MD5_DIGEST_LENGTH]) const;
    static std::string digest_to_hex_string(const unsigned char digest[MD5_DIGEST_LENGTH]) noexcept;
public:
    std::optional<std::string> computeFileHashMD5(const std::filesystem::path& file_path) const;
};

