#pragma once

#include "core/directory_walker.hpp"
#include "core/hash_database.hpp"
#include "core/scanner.hpp"
#include "utils/file_logger.hpp"
#include "utils/path_validator.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct ScanConfig {
  std::string csv_path;
  std::string log_path;
  std::string scan_path;
  size_t thread_count = 4;
  std::string algorithm = "SHA256";
};

struct MaliciousRecord {
  std::string path;
  std::string verdict;
};

class ScanController {
 public:
  ScanController();
  ~ScanController();

  ScanController(const ScanController&) = delete;
  ScanController& operator=(const ScanController&) = delete;

                                                                      
                                                                        
                                                                           
  bool Start(const ScanConfig& config);
  void Wait();

  bool IsDone() const noexcept { return done_.load(); }
  bool HasError() const;
  std::string GetErrorMessage() const;

  Scanner::ScanResult GetStats() const;
  std::vector<MaliciousRecord> GetThreats() const;
  std::chrono::milliseconds GetElapsed() const;

 private:
  FileLogger logger_;
  PathValidator path_validator_;
  DirectoryWalker directory_walker_;
  std::unique_ptr<HashDatabase> hash_database_;
  std::unique_ptr<Scanner> scanner_;

  std::thread scan_thread_;
  std::atomic<bool> done_{true};

  mutable std::mutex error_mutex_;
  std::string error_message_;

  mutable std::mutex threats_mutex_;
  std::vector<MaliciousRecord> threats_;

  Scanner::ScanResult result_{0, 0, 0, 0, std::chrono::milliseconds{0}};
  std::chrono::steady_clock::time_point start_time_;
};
