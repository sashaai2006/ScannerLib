#include <gtest/gtest.h>

#include "core/scanner.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace {

// MD5("abc") — содержимое "вредоносного" файла в тестах.
constexpr const char* kMaliciousContent = "abc";
constexpr const char* kMaliciousHash = "900150983cd24fb0d6963f7d28e17f72";

class ScannerIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() /
                    ("scanner_it_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        scan_dir_ = test_dir_ / "scan";
        std::filesystem::create_directories(scan_dir_ / "sub");

        WriteFile(scan_dir_ / "clean1.txt", "clean content one");
        WriteFile(scan_dir_ / "sub" / "clean2.txt", "clean content two");
        WriteFile(scan_dir_ / "sub" / "evil.bin", kMaliciousContent);

        csv_path_ = (test_dir_ / "base.csv").string();
        std::ofstream(csv_path_) << kMaliciousHash << ";Trojan.Test\n";

        log_path_ = (test_dir_ / "logs" / "scan.log").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    static void WriteFile(const std::filesystem::path& path, const std::string& content) {
        std::ofstream out(path, std::ios::binary);
        out << content;
    }

    std::string ReadLog() const {
        std::ifstream in(log_path_);
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    std::filesystem::path test_dir_;
    std::filesystem::path scan_dir_;
    std::string csv_path_;
    std::string log_path_;
};

TEST_F(ScannerIntegrationTest, EndToEndFindsMaliciousFile) {
    Scanner scanner(csv_path_, log_path_, 2);
    const auto result = scanner.Scan(scan_dir_);

    EXPECT_EQ(result.total_files, 3);
    EXPECT_EQ(result.malicious_files, 1);
    EXPECT_EQ(result.errors, 0);

    const std::string log = ReadLog();
    EXPECT_NE(log.find("Trojan.Test"), std::string::npos);
    EXPECT_NE(log.find("evil.bin"), std::string::npos);
    EXPECT_NE(log.find(kMaliciousHash), std::string::npos);
}

TEST_F(ScannerIntegrationTest, ThrowsOnMissingScanDirectory) {
    Scanner scanner(csv_path_, log_path_, 2);
    EXPECT_THROW(scanner.Scan(test_dir_ / "no_such_dir"), std::runtime_error);
}

TEST_F(ScannerIntegrationTest, ThrowsOnMissingHashBase) {
    EXPECT_THROW(Scanner((test_dir_ / "missing.csv").string(), log_path_, 2),
                 std::runtime_error);
}

TEST_F(ScannerIntegrationTest, RepeatedScanResetsCounters) {
    Scanner scanner(csv_path_, log_path_, 2);

    const auto first = scanner.Scan(scan_dir_);
    EXPECT_EQ(first.total_files, 3);
    EXPECT_EQ(first.malicious_files, 1);

    const auto second = scanner.Scan(scan_dir_ / "sub");
    EXPECT_EQ(second.total_files, 2);
    EXPECT_EQ(second.malicious_files, 1);
    EXPECT_EQ(second.errors, 0);
}

TEST_F(ScannerIntegrationTest, GetCurrentStatsReflectsLastScan) {
    Scanner scanner(csv_path_, log_path_, 2);
    scanner.Scan(scan_dir_);

    const auto stats = scanner.GetCurrentStats();
    EXPECT_EQ(stats.total_files, 3);
    EXPECT_EQ(stats.malicious_files, 1);
    EXPECT_EQ(stats.errors, 0);
}

TEST_F(ScannerIntegrationTest, UnreadableFileCountsAsError) {
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root может читать файлы с правами 000, тест неприменим";
    }

    const auto secret = scan_dir_ / "secret.txt";
    WriteFile(secret, "unreadable");
    std::filesystem::permissions(secret, std::filesystem::perms::none);

    Scanner scanner(csv_path_, log_path_, 2);
    const auto result = scanner.Scan(scan_dir_);

    std::filesystem::permissions(secret, std::filesystem::perms::owner_all);

    EXPECT_EQ(result.errors, 1);
    EXPECT_EQ(result.total_files, 3);
}

TEST_F(ScannerIntegrationTest, ManyFilesScannedCorrectly) {
    constexpr int kExtraFiles = 200;
    for (int i = 0; i < kExtraFiles; ++i) {
        WriteFile(scan_dir_ / ("file_" + std::to_string(i) + ".txt"),
                  "content number " + std::to_string(i));
    }

    Scanner scanner(csv_path_, log_path_, 8);
    const auto result = scanner.Scan(scan_dir_);

    EXPECT_EQ(result.total_files, 3 + kExtraFiles);
    EXPECT_EQ(result.malicious_files, 1);
    EXPECT_EQ(result.errors, 0);
}

} // namespace
