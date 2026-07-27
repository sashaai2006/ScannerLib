#include <gtest/gtest.h>

#include "core/hash_base.hpp"

#include <filesystem>
#include <fstream>
#include <string>

namespace {

class HashBaseTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ =
        std::filesystem::temp_directory_path() /
        ("hashbase_test_" +
         std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
         "_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
    std::filesystem::create_directories(test_dir_);
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(test_dir_, ec);
  }

  std::string WriteCsv(const std::string& content) {
    const auto path = test_dir_ / "base.csv";
    std::ofstream out(path);
    out << content;
    out.close();
    return path.string();
  }

  std::filesystem::path test_dir_;
};

TEST_F(HashBaseTest, LoadsAndFindsVerdicts) {
  const auto csv = WriteCsv(
      "d41d8cd98f00b204e9800998ecf8427e;Trojan.Empty\n"
      "900150983cd24fb0d6963f7d28e17f72;Virus.Abc\n");

  HashBase base;
  base.LoadHashes(csv);

  const std::string* v1 = base.GetVerdict("d41d8cd98f00b204e9800998ecf8427e");
  ASSERT_NE(v1, nullptr);
  EXPECT_EQ(*v1, "Trojan.Empty");

  const std::string* v2 = base.GetVerdict("900150983cd24fb0d6963f7d28e17f72");
  ASSERT_NE(v2, nullptr);
  EXPECT_EQ(*v2, "Virus.Abc");
}

TEST_F(HashBaseTest, LookupIsCaseInsensitive) {
  const auto csv = WriteCsv("abcdef0123456789abcdef0123456789;Malware.X\n");

  HashBase base;
  base.LoadHashes(csv);

  EXPECT_NE(base.GetVerdict("ABCDEF0123456789ABCDEF0123456789"), nullptr);
  EXPECT_NE(base.GetVerdict("abcdef0123456789abcdef0123456789"), nullptr);
}

TEST_F(HashBaseTest, UppercaseHashesInBaseAreNormalized) {
  const auto csv = WriteCsv("ABCDEF0123456789ABCDEF0123456789;Malware.Y\n");

  HashBase base;
  base.LoadHashes(csv);

  const std::string* v = base.GetVerdict("abcdef0123456789abcdef0123456789");
  ASSERT_NE(v, nullptr);
  EXPECT_EQ(*v, "Malware.Y");
}

TEST_F(HashBaseTest, ReturnsNullptrForUnknownHash) {
  const auto csv = WriteCsv("d41d8cd98f00b204e9800998ecf8427e;Trojan.Empty\n");

  HashBase base;
  base.LoadHashes(csv);

  EXPECT_EQ(base.GetVerdict("00000000000000000000000000000000"), nullptr);
}

TEST_F(HashBaseTest, SkipsMalformedLines) {
  const auto csv = WriteCsv(
      "line-without-delimiter\n"
      "\n"
      ";NoHash\n"
      "d41d8cd98f00b204e9800998ecf8427e;\n"
      "900150983cd24fb0d6963f7d28e17f72;Virus.Abc\n");

  HashBase base;
  base.LoadHashes(csv);

  EXPECT_EQ(base.GetVerdict("d41d8cd98f00b204e9800998ecf8427e"), nullptr);
  const std::string* v = base.GetVerdict("900150983cd24fb0d6963f7d28e17f72");
  ASSERT_NE(v, nullptr);
  EXPECT_EQ(*v, "Virus.Abc");
}

TEST_F(HashBaseTest, TrimsWhitespaceAroundFields) {
  const auto csv =
      WriteCsv("  900150983cd24fb0d6963f7d28e17f72  ;  Virus.Abc  \n");

  HashBase base;
  base.LoadHashes(csv);

  const std::string* v = base.GetVerdict("900150983cd24fb0d6963f7d28e17f72");
  ASSERT_NE(v, nullptr);
  EXPECT_EQ(*v, "Virus.Abc");
}

TEST_F(HashBaseTest, ThrowsOnMissingFile) {
  HashBase base;
  EXPECT_THROW(base.LoadHashes((test_dir_ / "nonexistent.csv").string()),
               std::runtime_error);
}

}  // namespace
