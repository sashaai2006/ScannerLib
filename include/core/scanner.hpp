#pragma once

#include "core/ihash_database.hpp"
#include "core/ifile_enumerator.hpp"
#include "crypto/hash_compute.hpp"
#include "threading/thread_pool.hpp"
#include "utils/ilogger.hpp"
#include "utils/ipath_validator.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string_view>

class Scanner {
 public:
  struct ScanResult {
    size_t total_files;
    size_t total_expected_files;
    size_t malicious_files;
    size_t errors;
    std::chrono::milliseconds duration;
    bool cancelled;
  };

  using MaliciousCallback = std::function<void(const std::filesystem::path&,
                                               std::string_view hash,
                                               std::string_view verdict)>;

  Scanner(const IHashDatabase& hash_database,
          std::unique_ptr<IHashCompute> hash_compute,
          IFileEnumerator& file_enumerator,
          const IPathValidator& path_validator, ILogger& logger,
          size_t thread_count = 0);
  ~Scanner() noexcept;

  ScanResult Scan(const std::filesystem::path& root_path);
  ScanResult GetCurrentStats() const noexcept;
  void SetMaliciousCallback(MaliciousCallback callback);
  void RequestStop();
  bool IsStopRequested() const noexcept { return stop_.load(); }

 private:
  static constexpr size_t kDefaultThreadCount = 4;
  static constexpr size_t kQueueCapacityMultiplier = 32;

  void EnqueueScanTasks(const std::filesystem::path& root_path);
  void ProcessFile(const std::filesystem::path& file_path);
  void LogMaliciousFile(const std::filesystem::path& file_path,
                        std::string_view hash, std::string_view verdict);

  const IHashDatabase& hash_database_;
  std::unique_ptr<IHashCompute> hash_compute_;
  IFileEnumerator& file_enumerator_;
  const IPathValidator& path_validator_;
  ILogger& logger_;
  ThreadPool thread_pool_;

  std::atomic<size_t> total_files_{0};
  std::atomic<size_t> total_expected_files_{0};
  std::atomic<size_t> malicious_files_{0};
  std::atomic<size_t> errors_{0};
  std::atomic<bool> stop_{false};

  std::mutex callback_mutex_;
  MaliciousCallback malicious_callback_;
};
