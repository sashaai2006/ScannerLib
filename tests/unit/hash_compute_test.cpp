#include "crypto/hash_compute.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

class HashComputeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ =
        std::filesystem::temp_directory_path() /
        ("hash_compute_test_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
    std::filesystem::create_directories(test_dir_);
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(test_dir_, ec);
  }

  std::filesystem::path WriteFile(const std::string& name,
                                  const std::string& content) {
    const auto path = test_dir_ / name;
    std::ofstream out(path, std::ios::binary);
    out << content;
    out.close();
    return path;
  }

  std::filesystem::path test_dir_;
};

TEST_F(HashComputeTest, Md5KnownVectorAbc) {
  const auto path = WriteFile("abc.txt", "abc");

  HashCompute hasher("md5");
  const auto hash = hasher.ComputeFileHash(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash, "900150983cd24fb0d6963f7d28e17f72");
  EXPECT_EQ(hasher.AlgorithmName(), "MD5");
  EXPECT_TRUE(hasher.IsDeprecated());
}

TEST_F(HashComputeTest, Sha1KnownVectorAbc) {
  const auto path = WriteFile("abc.txt", "abc");

  HashCompute hasher("SHA1");
  const auto hash = hasher.ComputeFileHash(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash, "a9993e364706816aba3e25717850c26c9cd0d89d");
  EXPECT_EQ(hasher.AlgorithmName(), "SHA1");
  EXPECT_FALSE(hasher.IsDeprecated());
}

TEST_F(HashComputeTest, Sha256KnownVectorAbc) {
  const auto path = WriteFile("abc.txt", "abc");

  HashCompute hasher("Sha256");
  const auto hash = hasher.ComputeFileHash(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  EXPECT_EQ(hasher.AlgorithmName(), "SHA256");
  EXPECT_FALSE(hasher.IsDeprecated());
}

TEST_F(HashComputeTest, Sha256KnownVectorEmptyFile) {
  const auto path = WriteFile("empty.bin", "");

  HashCompute hasher("SHA256");
  const auto hash = hasher.ComputeFileHash(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(HashComputeTest, Sha256KnownVectorMillionA) {
  const auto path = WriteFile("million.bin", std::string(1000000, 'a'));

  HashCompute hasher("SHA256");
  const auto hash = hasher.ComputeFileHash(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_F(HashComputeTest, ReturnsNulloptForMissingFile) {
  HashCompute hasher("SHA256");
  EXPECT_FALSE(hasher.ComputeFileHash(test_dir_ / "no_such_file.bin").has_value());
}

TEST_F(HashComputeTest, ReturnsNulloptForDirectory) {
  HashCompute hasher("SHA256");
  EXPECT_FALSE(hasher.ComputeFileHash(test_dir_).has_value());
}

TEST_F(HashComputeTest, ThrowsOnUnsupportedAlgorithm) {
  EXPECT_THROW(HashCompute("md4"), std::invalid_argument);
}

TEST_F(HashComputeTest, ListsAvailableAlgorithms) {
  const auto& algorithms = HashCompute::AvailableAlgorithms();
  EXPECT_GE(algorithms.size(), 3u);

  bool has_md5 = false;
  bool has_sha256 = false;
  for (const auto& info : algorithms) {
    if (info.name == "MD5") {
      has_md5 = true;
      EXPECT_TRUE(info.deprecated);
    }
    if (info.name == "SHA256") {
      has_sha256 = true;
      EXPECT_FALSE(info.deprecated);
    }
  }
  EXPECT_TRUE(has_md5);
  EXPECT_TRUE(has_sha256);
}

TEST_F(HashComputeTest, IsSupportedCaseInsensitive) {
  EXPECT_TRUE(HashCompute::IsSupported("md5"));
  EXPECT_TRUE(HashCompute::IsSupported("SHA256"));
  EXPECT_TRUE(HashCompute::IsSupported("Sha1"));
  EXPECT_FALSE(HashCompute::IsSupported("md4"));
}

}  // namespace
