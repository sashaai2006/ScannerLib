#include "crypto/hash_algorithms.hpp"

#include <openssl/evp.h>

Md5Compute::Md5Compute() : HashComputeBase("MD5", true, EVP_md5()) {}

Sha1Compute::Sha1Compute() : HashComputeBase("SHA1", false, EVP_sha1()) {}

Sha256Compute::Sha256Compute()
    : HashComputeBase("SHA256", false, EVP_sha256()) {}
