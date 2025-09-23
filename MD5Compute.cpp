#include "MD5Compute.h"
#include <openssl/md5.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

std::optional<std::ifstream> MD5Compute::open_file_for_reading(const std::filesystem::path& file_path) const {
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


bool MD5Compute::compute_md5_digest(std::ifstream& file, unsigned char digest[MD5_DIGEST_LENGTH]) const {
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

std::string MD5Compute::digest_to_hex_string(const unsigned char digest[MD5_DIGEST_LENGTH]) noexcept {
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        hex_stream << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    return hex_stream.str();
}

std::optional<std::string> MD5Compute::computeFileHashMD5(const std::filesystem::path& file_path) const {
    try {
        auto file_opt = open_file_for_reading(file_path);
        if (!file_opt.has_value()) {
            return std::nullopt;
        }

        unsigned char digest[MD5_DIGEST_LENGTH];
        if (!compute_md5_digest(file_opt.value(), digest)) {
            return std::nullopt;
        }
        return digest_to_hex_string(digest);

    } catch (const std::exception&) {
        return std::nullopt;
    }
}
