#include "core/scan_controller.hpp"

#include "core/csv_hash_source.hpp"
#include "crypto/hash_compute_factory.hpp"

#include <exception>
#include <utility>

ScanController::ScanController() = default;

ScanController::~ScanController() {
  Wait();
}

bool ScanController::Start(const ScanConfig& config) {
  {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_message_.clear();
  }

  try {
    path_validator_.ValidateScanInputs(config.csv_path, config.log_path, "");

    logger_.Open(config.log_path);

    CsvHashSource source(config.csv_path, logger_);
    hash_database_ = std::make_unique<HashDatabase>(source.Load());

    auto hash_compute = HashComputeFactory::Create(config.algorithm);

    scanner_ = std::make_unique<Scanner>(*hash_database_,
                                         std::move(hash_compute),
                                         directory_walker_, path_validator_,
                                         logger_, config.thread_count);
  } catch (const std::exception& e) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_message_ = e.what();
    return false;
  }

  scanner_->SetMaliciousCallback(
      [this](const std::filesystem::path& file_path,
             std::string_view /*hash*/, std::string_view verdict) {
        std::lock_guard<std::mutex> lock(threats_mutex_);
        threats_.push_back({file_path.string(), std::string(verdict)});
      });

  {
    std::lock_guard<std::mutex> lock(threats_mutex_);
    threats_.clear();
  }

  start_time_ = std::chrono::steady_clock::now();
  done_ = false;

  Wait();

  scan_thread_ = std::thread([this, scan_path = config.scan_path]() {
    try {
      result_ = scanner_->Scan(scan_path);
    } catch (const std::exception& e) {
      std::lock_guard<std::mutex> lock(error_mutex_);
      error_message_ = std::string("Ошибка сканирования: ") + e.what();
    }
    done_ = true;
  });

  return true;
}

void ScanController::Wait() {
  if (scan_thread_.joinable()) {
    scan_thread_.join();
  }
}

bool ScanController::HasError() const {
  std::lock_guard<std::mutex> lock(error_mutex_);
  return !error_message_.empty();
}

std::string ScanController::GetErrorMessage() const {
  std::lock_guard<std::mutex> lock(error_mutex_);
  return error_message_;
}

Scanner::ScanResult ScanController::GetStats() const {
  if (done_.load()) {
    return result_;
  }
  if (scanner_) {
    return scanner_->GetCurrentStats();
  }
  return Scanner::ScanResult{0, 0, 0, 0, std::chrono::milliseconds{0}};
}

std::vector<MaliciousRecord> ScanController::GetThreats() const {
  std::lock_guard<std::mutex> lock(threats_mutex_);
  return threats_;
}

std::chrono::milliseconds ScanController::GetElapsed() const {
  if (done_.load()) {
    return result_.duration;
  }
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start_time_);
}
