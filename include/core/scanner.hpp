#pragma once

#include "core/hash_base.hpp"
#include "crypto/md5_compute.hpp"
#include "threading/thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

class Scanner {
 private:
  std::unique_ptr<HashBase> hash_base_;
  std::unique_ptr<MD5Compute> md5_compute_;
  std::unique_ptr<ThreadPool<std::function<void()>>> thread_pool_;
  size_t thread_count_;
  std::string csv_path_;
  std::string log_path_;

 private:
  std::atomic<size_t> total_files_{0};
  std::atomic<size_t> malicious_files_{0};
  std::atomic<size_t> errors_{0};

 private:
  static constexpr size_t DEFAULT_THREAD_COUNT = 4;

 private:
  void ProcessFile(const std::filesystem::path& file_path);
  void EnqueueScanTasks(const std::filesystem::path& root_path);
  void LogMaliciousFile(const std::filesystem::path& file_path,
                        const std::string& hash,
                        const std::string& verdict);

 public:
  using MaliciousCallback = std::function<void(const std::filesystem::path&,
                                               const std::string& hash,
                                               const std::string& verdict)>;

  Scanner(const std::string& csv_path,
          const std::string& log_path,
          size_t thread_count = 0);
  ~Scanner() noexcept;
  struct ScanResult {
    size_t total_files;
    size_t malicious_files;
    size_t errors;
    std::chrono::milliseconds duration;
  };

  ScanResult Scan(const std::filesystem::path& root_path);
  ScanResult GetCurrentStats() const noexcept;
  void SetMaliciousCallback(MaliciousCallback callback);

 private:
  MaliciousCallback malicious_callback_;
};
