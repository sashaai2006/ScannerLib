#pragma once

#include "crypto/hash_compute.hpp"

class Md5Compute : public HashComputeBase {
 public:
  Md5Compute();
};

class Sha1Compute : public HashComputeBase {
 public:
  Sha1Compute();
};

class Sha256Compute : public HashComputeBase {
 public:
  Sha256Compute();
};
