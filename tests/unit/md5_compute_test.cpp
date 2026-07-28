#include "crypto/md5_compute.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

class MD5ComputeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ =
        std::filesystem::temp_directory_path() /
        ("md5_test_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
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

TEST_F(MD5ComputeTest, KnownVectorAbc) {
  const auto path = WriteFile("abc.txt", "abc");

  MD5Compute md5;
  const auto hash = md5.ComputeFileHashMD5(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash, "900150983cd24fb0d6963f7d28e17f72");
}

TEST_F(MD5ComputeTest, KnownVectorEmptyFile) {
  const auto path = WriteFile("empty.bin", "");

  MD5Compute md5;
  const auto hash = md5.ComputeFileHashMD5(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash, "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(MD5ComputeTest, KnownVectorMillionA) {
  const auto path = WriteFile("million.bin", std::string(1000000, 'a'));

  MD5Compute md5;
  const auto hash = md5.ComputeFileHashMD5(path);

  ASSERT_TRUE(hash.has_value());
  EXPECT_EQ(*hash, "7707d6ae4e027c70eea2a935c2296f21");
}

TEST_F(MD5ComputeTest, ReturnsNulloptForMissingFile) {
  MD5Compute md5;
  EXPECT_FALSE(
      md5.ComputeFileHashMD5(test_dir_ / "no_such_file.bin").has_value());
}

TEST_F(MD5ComputeTest, ReturnsNulloptForDirectory) {
  MD5Compute md5;
  EXPECT_FALSE(md5.ComputeFileHashMD5(test_dir_).has_value());
}

}  // namespace
