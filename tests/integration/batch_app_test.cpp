#include "core/scan_controller.hpp"
#include "tui/batch_app.hpp"
#include "tui/cli_options.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace {

constexpr const char* kMaliciousContent = "abc";
constexpr const char* kMaliciousHash =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

class BatchAppTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ = std::filesystem::temp_directory_path() /
                ("batch_it_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
    scan_dir_ = test_dir_ / "scan";
    std::filesystem::create_directories(scan_dir_);

    std::ofstream(scan_dir_ / "clean.txt") << "clean";
    std::ofstream(scan_dir_ / "evil.bin", std::ios::binary) << kMaliciousContent;

    csv_path_ = (test_dir_ / "base.csv").string();
    std::ofstream(csv_path_) << kMaliciousHash << ";Trojan.Test\n";
    log_path_ = (test_dir_ / "scan.log").string();
    report_path_ = (test_dir_ / "report.json").string();
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(test_dir_, ec);
  }

  std::filesystem::path test_dir_;
  std::filesystem::path scan_dir_;
  std::string csv_path_;
  std::string log_path_;
  std::string report_path_;
};

TEST_F(BatchAppTest, WritesJsonReport) {
  CliOptions options;
  options.base_path = csv_path_;
  options.log_path = log_path_;
  options.scan_path = scan_dir_.string();
  options.threads = "2";
  options.algorithm = "SHA256";
  options.batch = true;
  options.report_path = report_path_;

  EXPECT_EQ(BatchApp::Run(options), 0);

  std::ifstream in(report_path_);
  ASSERT_TRUE(in);
  std::ostringstream ss;
  ss << in.rdbuf();
  const std::string json = ss.str();

  EXPECT_NE(json.find("\"status\": \"ok\""), std::string::npos);
  EXPECT_NE(json.find("\"malicious_files\": 1"), std::string::npos);
  EXPECT_NE(json.find("Trojan.Test"), std::string::npos);
  EXPECT_NE(json.find("evil.bin"), std::string::npos);
}

}  
