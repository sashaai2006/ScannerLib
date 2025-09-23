#pragma once

#ifndef DLL_EXPORT
#  ifdef _WIN32
#    define DLL_EXPORT __declspec(dllexport)
#  else
#    define DLL_EXPORT
#  endif
#endif


#include <string>
#include <fstream>
#include <filesystem>
#include <atomic>
#include <mutex>
#include <memory>
#include <chrono>
#include "ThreadPool.h"
#include "HashBase.h"
#include "MD5Compute.h"


class DLL_EXPORT Scanner {
private:
  std::unique_ptr<HashBase> hash_base_;         
  std::unique_ptr<MD5Compute> md5_compute_; 
  std::unique_ptr<ThreadPool<std::function<void()>>> thread_pool_; 
private:
  std::ofstream log_file_;                
private:
  std::atomic<size_t> total_files_{0};   
  std::atomic<size_t> malicious_files_{0};      
  std::atomic<size_t> errors_{0};   
  mutable std::mutex log_mutex_;     
private:
  static constexpr size_t DEFAULT_THREAD_COUNT = 4;

private:
    void process_file(const std::filesystem::path& file_path);
    void enqueue_scan_tasks(const std::filesystem::path& root_path);
    void log_malicious_file(const std::filesystem::path& file_path, 
                           const std::string& hash, 
                           const std::string& verdict);

public:
  explicit Scanner(const std::string& csv_path, 
                     const std::string& log_path,
                     size_t thread_count = DEFAULT_THREAD_COUNT);
    ~Scanner() noexcept;
  struct ScanResult {
    size_t total_files;          
    size_t malicious_files;
    size_t errors; 
    std::chrono::milliseconds duration;
    };
    
  ScanResult Scan(const std::filesystem::path& root_path);
  ScanResult GetCurrentStats() const noexcept;
};
