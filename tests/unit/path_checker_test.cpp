#include "utils/validate_path.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

namespace {

class PathCheckerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ = std::filesystem::temp_directory_path() /
                ("pathchecker_test_" +
                 std::to_string(reinterpret_cast<uintptr_t>(this)));
    std::filesystem::create_directories(test_dir_);

    csv_path_ = (test_dir_ / "base.csv").string();
    std::ofstream(csv_path_) << "d41d8cd98f00b204e9800998ecf8427e;Verdict\n";
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(test_dir_, ec);
  }

  std::filesystem::path test_dir_;
  std::string csv_path_;
};

TEST_F(PathCheckerTest, ThrowsOnEmptyCsvPath) {
  EXPECT_THROW(PathChecker::ValidatePaths("", "log.txt", ""),
               std::runtime_error);
}

TEST_F(PathCheckerTest, ThrowsOnEmptyLogPath) {
  EXPECT_THROW(PathChecker::ValidatePaths(csv_path_, "", ""),
               std::runtime_error);
}

TEST_F(PathCheckerTest, ThrowsOnMissingCsvFile) {
  EXPECT_THROW(PathChecker::ValidatePaths((test_dir_ / "missing.csv").string(),
                                          (test_dir_ / "log.txt").string(), ""),
               std::runtime_error);
}

TEST_F(PathCheckerTest, ThrowsWhenCsvIsDirectory) {
  EXPECT_THROW(PathChecker::ValidatePaths(test_dir_.string(),
                                          (test_dir_ / "log.txt").string(), ""),
               std::runtime_error);
}

TEST_F(PathCheckerTest, ThrowsOnMissingScanDirectory) {
  EXPECT_THROW(
      PathChecker::ValidatePaths(csv_path_, (test_dir_ / "log.txt").string(),
                                 (test_dir_ / "no_such_dir").string()),
      std::runtime_error);
}

TEST_F(PathCheckerTest, ThrowsWhenScanPathIsFile) {
  EXPECT_THROW(PathChecker::ValidatePaths(
                   csv_path_, (test_dir_ / "log.txt").string(), csv_path_),
               std::runtime_error);
}

TEST_F(PathCheckerTest, ValidPathsPassAndLogDirIsCreated) {
  const std::string log_path =
      (test_dir_ / "nested" / "logs" / "scan.log").string();

  EXPECT_NO_THROW(
      PathChecker::ValidatePaths(csv_path_, log_path, test_dir_.string()));
  EXPECT_TRUE(std::filesystem::exists(test_dir_ / "nested" / "logs"));
}

TEST_F(PathCheckerTest, IsValidHashBaseChecks) {
  EXPECT_TRUE(PathChecker::IsValidHashBase(csv_path_));
  EXPECT_FALSE(
      PathChecker::IsValidHashBase((test_dir_ / "missing.csv").string()));
  EXPECT_FALSE(PathChecker::IsValidHashBase(test_dir_.string()));
}

TEST_F(PathCheckerTest, IsValidScanDirectoryChecks) {
  EXPECT_TRUE(PathChecker::IsValidScanDirectory(test_dir_.string()));
  EXPECT_FALSE(PathChecker::IsValidScanDirectory(csv_path_));
  EXPECT_FALSE(
      PathChecker::IsValidScanDirectory((test_dir_ / "missing").string()));
}

TEST_F(PathCheckerTest, IsValidLogPathCreatesFile) {
  const std::string log_path = (test_dir_ / "check.log").string();
  EXPECT_TRUE(PathChecker::IsValidLogPath(log_path));
  EXPECT_TRUE(std::filesystem::exists(log_path));
}

}  // namespace
