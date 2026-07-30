#include "core/csv_hash_source.hpp"
#include "core/hash_database.hpp"
#include "utils/file_logger.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>

namespace {

class NullLogger : public ILogger {
 public:
  void Log(Level, std::string_view) override {}
};

class HashDatabaseTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ =
        std::filesystem::temp_directory_path() /
        ("hashdb_test_" +
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
  NullLogger logger_;
};

TEST_F(HashDatabaseTest, CsvSourceLoadsAndDatabaseFindsVerdicts) {
  const auto csv = WriteCsv(
      "d41d8cd98f00b204e9800998ecf8427e;Trojan.Empty\n"
      "900150983cd24fb0d6963f7d28e17f72;Virus.Abc\n");

  CsvHashSource source(csv, logger_);
  HashDatabase database(source.Load());

  const auto v1 = database.GetVerdict("d41d8cd98f00b204e9800998ecf8427e");
  ASSERT_TRUE(v1.has_value());
  EXPECT_EQ(*v1, "Trojan.Empty");

  const auto v2 = database.GetVerdict("900150983cd24fb0d6963f7d28e17f72");
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(*v2, "Virus.Abc");
}

TEST_F(HashDatabaseTest, LookupIsCaseInsensitive) {
  CsvHashSource source(
      WriteCsv("abcdef0123456789abcdef0123456789;Malware.X\n"), logger_);
  HashDatabase database(source.Load());

  EXPECT_TRUE(database.GetVerdict("ABCDEF0123456789ABCDEF0123456789").has_value());
  EXPECT_TRUE(database.GetVerdict("abcdef0123456789abcdef0123456789").has_value());
}

TEST_F(HashDatabaseTest, UppercaseHashesInBaseAreNormalized) {
  CsvHashSource source(
      WriteCsv("ABCDEF0123456789ABCDEF0123456789;Malware.Y\n"), logger_);
  HashDatabase database(source.Load());

  const auto v = database.GetVerdict("abcdef0123456789abcdef0123456789");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "Malware.Y");
}

TEST_F(HashDatabaseTest, ReturnsNulloptForUnknownHash) {
  CsvHashSource source(
      WriteCsv("d41d8cd98f00b204e9800998ecf8427e;Trojan.Empty\n"), logger_);
  HashDatabase database(source.Load());

  EXPECT_FALSE(database.GetVerdict("00000000000000000000000000000000").has_value());
}

TEST_F(HashDatabaseTest, CsvSourceSkipsMalformedLines) {
  const auto csv = WriteCsv(
      "line-without-delimiter\n"
      "\n"
      ";NoHash\n"
      "d41d8cd98f00b204e9800998ecf8427e;\n"
      "900150983cd24fb0d6963f7d28e17f72;Virus.Abc\n");

  CsvHashSource source(csv, logger_);
  HashDatabase database(source.Load());

  EXPECT_FALSE(database.GetVerdict("d41d8cd98f00b204e9800998ecf8427e").has_value());
  const auto v = database.GetVerdict("900150983cd24fb0d6963f7d28e17f72");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "Virus.Abc");
}

TEST_F(HashDatabaseTest, CsvSourceTrimsWhitespaceAroundFields) {
  const auto csv =
      WriteCsv("  900150983cd24fb0d6963f7d28e17f72  ;  Virus.Abc  \n");

  CsvHashSource source(csv, logger_);
  HashDatabase database(source.Load());

  const auto v = database.GetVerdict("900150983cd24fb0d6963f7d28e17f72");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "Virus.Abc");
}

TEST_F(HashDatabaseTest, CsvSourceThrowsOnMissingFile) {
  CsvHashSource source((test_dir_ / "nonexistent.csv").string(), logger_);
  EXPECT_THROW(source.Load(), std::runtime_error);
}

TEST_F(HashDatabaseTest, DatabaseConstructibleFromMapDirectly) {
  std::unordered_map<std::string, std::string> hashes = {
      {"900150983cd24fb0d6963f7d28e17f72", "Virus.Abc"}};
  HashDatabase database(std::move(hashes));

  const auto v = database.GetVerdict("900150983cd24fb0d6963f7d28e17f72");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "Virus.Abc");
}

}  // namespace
