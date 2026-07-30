#include "utils/path_validator.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace {

class PathValidatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ = std::filesystem::temp_directory_path() /
                ("pathval_test_" +
                 std::to_string(reinterpret_cast<uintptr_t>(this)));
    std::filesystem::create_directories(test_dir_);
    csv_path_ = (test_dir_ / "base.csv").string();
    std::ofstream(csv_path_) << "hash;verdict\n";
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(test_dir_, ec);
  }

  std::filesystem::path test_dir_;
  std::string csv_path_;
  PathValidator validator_;
};

TEST_F(PathValidatorTest, ThrowsOnEmptyCsvPath) {
  EXPECT_THROW(validator_.ValidateScanInputs("", (test_dir_ / "log.txt").string(), ""),
               std::runtime_error);
}

TEST_F(PathValidatorTest, ThrowsOnEmptyLogPath) {
  EXPECT_THROW(validator_.ValidateScanInputs(csv_path_, "", ""),
               std::runtime_error);
}

TEST_F(PathValidatorTest, ThrowsOnMissingCsvFile) {
  EXPECT_THROW(validator_.ValidateScanInputs(
                   (test_dir_ / "missing.csv").string(),
                   (test_dir_ / "log.txt").string(), ""),
               std::runtime_error);
}

TEST_F(PathValidatorTest, ThrowsWhenCsvIsDirectory) {
  EXPECT_THROW(validator_.ValidateScanInputs(
                   test_dir_.string(), (test_dir_ / "log.txt").string(), ""),
               std::runtime_error);
}

TEST_F(PathValidatorTest, ThrowsOnMissingScanDirectory) {
  EXPECT_THROW(validator_.ValidateScanInputs(
                   csv_path_, (test_dir_ / "log.txt").string(),
                   (test_dir_ / "no_such_dir").string()),
               std::runtime_error);
}

TEST_F(PathValidatorTest, ThrowsWhenScanPathIsFile) {
  EXPECT_THROW(validator_.ValidateScanInputs(csv_path_,
                                             (test_dir_ / "log.txt").string(),
                                             csv_path_),
               std::runtime_error);
}

TEST_F(PathValidatorTest, ValidPathsPassAndLogDirIsCreated) {
  const auto log_path = (test_dir_ / "logs" / "scan.log").string();
  EXPECT_NO_THROW(validator_.ValidateScanInputs(csv_path_, log_path,
                                                test_dir_.string()));
  EXPECT_TRUE(std::filesystem::exists(test_dir_ / "logs"));
}

TEST_F(PathValidatorTest, ValidateScanTargetRejectsMissingDirectory) {
  EXPECT_THROW(validator_.ValidateScanTarget((test_dir_ / "missing").string()),
               std::runtime_error);
}

TEST_F(PathValidatorTest, ValidateScanTargetRejectsFile) {
  EXPECT_THROW(validator_.ValidateScanTarget(csv_path_), std::runtime_error);
}

TEST_F(PathValidatorTest, ValidateScanTargetAcceptsDirectory) {
  EXPECT_NO_THROW(validator_.ValidateScanTarget(test_dir_.string()));
}

}  // namespace
