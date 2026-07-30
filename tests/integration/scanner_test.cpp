#include "core/scanner.hpp"

#include "core/csv_hash_source.hpp"
#include "core/directory_walker.hpp"
#include "core/hash_database.hpp"
#include "crypto/hash_compute_factory.hpp"
#include "utils/file_logger.hpp"
#include "utils/path_validator.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace {

// SHA256("abc") — содержимое "вредоносного" файла в тестах.
constexpr const char* kMaliciousContent = "abc";
constexpr const char* kMaliciousHash =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

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

  static void WriteFile(const std::filesystem::path& path,
                        const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    out << content;
  }

  std::string ReadLog() const {
    std::ifstream in(log_path_);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
  }

  // Создаёт Scanner с реальными зависимостями (composition root для тестов).
  std::unique_ptr<Scanner> MakeScanner(
      size_t thread_count, const std::string& algorithm = "SHA256",
      const std::string& csv_path = "") {
    logger_.Open(log_path_);

    CsvHashSource source(csv_path.empty() ? csv_path_ : csv_path, logger_);
    hash_database_ = std::make_unique<HashDatabase>(source.Load());

    auto hash_compute = HashComputeFactory::Create(algorithm);

    return std::make_unique<Scanner>(*hash_database_, std::move(hash_compute),
                                     directory_walker_, path_validator_,
                                     logger_, thread_count);
  }

  std::filesystem::path test_dir_;
  std::filesystem::path scan_dir_;
  std::string csv_path_;
  std::string log_path_;

  FileLogger logger_;
  PathValidator path_validator_;
  DirectoryWalker directory_walker_;
  std::unique_ptr<HashDatabase> hash_database_;
};

TEST_F(ScannerIntegrationTest, EndToEndFindsMaliciousFile) {
  auto scanner = MakeScanner(2);
  const auto result = scanner->Scan(scan_dir_);

  EXPECT_EQ(result.total_files, 3);
  EXPECT_EQ(result.malicious_files, 1);
  EXPECT_EQ(result.errors, 0);

  const std::string log = ReadLog();
  EXPECT_NE(log.find("Trojan.Test"), std::string::npos);
  EXPECT_NE(log.find("evil.bin"), std::string::npos);
  EXPECT_NE(log.find(kMaliciousHash), std::string::npos);
}

TEST_F(ScannerIntegrationTest, ThrowsOnMissingScanDirectory) {
  auto scanner = MakeScanner(2);
  EXPECT_THROW(scanner->Scan(test_dir_ / "no_such_dir"), std::runtime_error);
}

TEST_F(ScannerIntegrationTest, ThrowsOnMissingHashBase) {
  EXPECT_THROW(MakeScanner(2, "SHA256", (test_dir_ / "missing.csv").string()),
               std::runtime_error);
}

TEST_F(ScannerIntegrationTest, RepeatedScanResetsCounters) {
  auto scanner = MakeScanner(2);

  const auto first = scanner->Scan(scan_dir_);
  EXPECT_EQ(first.total_files, 3);
  EXPECT_EQ(first.malicious_files, 1);

  const auto second = scanner->Scan(scan_dir_ / "sub");
  EXPECT_EQ(second.total_files, 2);
  EXPECT_EQ(second.malicious_files, 1);
  EXPECT_EQ(second.errors, 0);
}

TEST_F(ScannerIntegrationTest, GetCurrentStatsReflectsLastScan) {
  auto scanner = MakeScanner(2);
  scanner->Scan(scan_dir_);

  const auto stats = scanner->GetCurrentStats();
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

  auto scanner = MakeScanner(2);
  const auto result = scanner->Scan(scan_dir_);

  std::filesystem::permissions(secret, std::filesystem::perms::owner_all);

  EXPECT_EQ(result.errors, 1);
  EXPECT_EQ(result.total_files, 3);
}

TEST_F(ScannerIntegrationTest, UnreadableDirectoryIsSkipped) {
  if (::geteuid() == 0) {
    GTEST_SKIP() << "root может читать директории с правами 000, тест неприменим";
  }

  const auto secret_dir = scan_dir_ / "secret_dir";
  std::filesystem::create_directory(secret_dir);
  WriteFile(secret_dir / "file.txt", "content");
  std::filesystem::permissions(secret_dir, std::filesystem::perms::none);

  auto scanner = MakeScanner(2);
  const auto result = scanner->Scan(scan_dir_);

  std::filesystem::permissions(secret_dir, std::filesystem::perms::owner_all);

  EXPECT_EQ(result.total_files, 3);
  EXPECT_EQ(result.errors, 1);

  const std::string log = ReadLog();
  EXPECT_NE(log.find("secret_dir"), std::string::npos);
  EXPECT_NE(log.find("Нет прав доступа к директории"), std::string::npos);
}

TEST_F(ScannerIntegrationTest, ManyFilesScannedCorrectly) {
  constexpr int kExtraFiles = 200;
  for (int i = 0; i < kExtraFiles; ++i) {
    WriteFile(scan_dir_ / ("file_" + std::to_string(i) + ".txt"),
              "content number " + std::to_string(i));
  }

  auto scanner = MakeScanner(8);
  const auto result = scanner->Scan(scan_dir_);

  EXPECT_EQ(result.total_files, 3 + kExtraFiles);
  EXPECT_EQ(result.malicious_files, 1);
  EXPECT_EQ(result.errors, 0);
}

TEST_F(ScannerIntegrationTest, ExplicitAlgorithmParameterIsRespected) {
  const std::string md5_csv = (test_dir_ / "md5_base.csv").string();
  std::ofstream(md5_csv) << "900150983cd24fb0d6963f7d28e17f72;Trojan.Md5\n";

  auto scanner = MakeScanner(2, "MD5", md5_csv);
  const auto result = scanner->Scan(scan_dir_);

  EXPECT_EQ(result.total_files, 3);
  EXPECT_EQ(result.malicious_files, 1);
  EXPECT_EQ(result.errors, 0);
}

TEST_F(ScannerIntegrationTest, MaliciousCallbackIsInvoked) {
  auto scanner = MakeScanner(2);

  std::vector<std::string> found;
  scanner->SetMaliciousCallback(
      [&found](const std::filesystem::path& path, std::string_view,
               std::string_view verdict) {
        found.push_back(path.filename().string() + ":" + std::string(verdict));
      });

  scanner->Scan(scan_dir_);

  ASSERT_EQ(found.size(), 1u);
  EXPECT_NE(found[0].find("evil.bin"), std::string::npos);
  EXPECT_NE(found[0].find("Trojan.Test"), std::string::npos);
}

}  // namespace
