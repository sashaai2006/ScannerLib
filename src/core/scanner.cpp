#include "core/scanner.hpp"

#include <stdexcept>
#include <string>
#include <utility>

Scanner::Scanner(const IHashDatabase& hash_database,
                 std::unique_ptr<IHashCompute> hash_compute,
                 IFileEnumerator& file_enumerator,
                 const IPathValidator& path_validator,
                 ILogger& logger,
                 size_t thread_count)
    : hash_database_(hash_database),
      hash_compute_(std::move(hash_compute)),
      file_enumerator_(file_enumerator),
      path_validator_(path_validator),
      logger_(logger),
      thread_pool_(thread_count == 0 ? kDefaultThreadCount : thread_count,
                   [&logger](std::string_view message) {
                     logger.Log(ILogger::Level::Error, message);
                   }) {
  logger_.Log(ILogger::Level::Info,
              "=== НОВАЯ СЕССИЯ СКАНИРОВАНИЯ НАЧАТА ===");
  logger_.Log(ILogger::Level::Info,
              "Алгоритм хеширования: " +
                  std::string(hash_compute_->AlgorithmName()) +
                  (hash_compute_->IsDeprecated() ? " (DEPRECATED)" : ""));
}

Scanner::~Scanner() noexcept {
  try {
    logger_.Log(ILogger::Level::Info,
                "=== СЕССИЯ СКАНИРОВАНИЯ ЗАВЕРШЕНА ===");
  } catch (...) {
  }
}

void Scanner::SetMaliciousCallback(MaliciousCallback callback) {
  std::lock_guard<std::mutex> lock(callback_mutex_);
  malicious_callback_ = std::move(callback);
}

Scanner::ScanResult Scanner::Scan(const std::filesystem::path& root_path) {
  const auto start_time = std::chrono::steady_clock::now();

  total_files_.store(0);
  total_expected_files_.store(0);
  malicious_files_.store(0);
  errors_.store(0);

  try {
    path_validator_.ValidateScanTarget(root_path.string());

    logger_.Log(ILogger::Level::Info,
                "Начинаем сканирование директории: " + root_path.string());

    CountFiles(root_path);
    EnqueueScanTasks(root_path);

    thread_pool_.Wait();

  } catch (const std::exception& e) {
    logger_.Log(ILogger::Level::Error,
                std::string("ОШИБКА при сканировании: ") + e.what());
    throw;
  }

  const auto end_time = std::chrono::steady_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  const ScanResult result{.total_files = total_files_.load(),
                          .total_expected_files = total_expected_files_.load(),
                          .malicious_files = malicious_files_.load(),
                          .errors = errors_.load(),
                          .duration = duration};

  logger_.Log(ILogger::Level::Info, "=== СТАТИСТИКА СКАНИРОВАНИЯ ===");
  logger_.Log(ILogger::Level::Info,
              "Всего файлов обработано: " + std::to_string(result.total_files));
  logger_.Log(ILogger::Level::Info,
              "Вредоносных файлов найдено: " +
                  std::to_string(result.malicious_files));
  logger_.Log(ILogger::Level::Info,
              "Ошибок обработки: " + std::to_string(result.errors));
  logger_.Log(ILogger::Level::Info,
              "Время выполнения: " + std::to_string(duration.count()) + " мс");

  return result;
}

void Scanner::CountFiles(const std::filesystem::path& root_path) {
  file_enumerator_.Enumerate(
      root_path,
      [this](const std::filesystem::path&) { total_expected_files_.fetch_add(1); },
      [](const std::filesystem::path&, const std::string&) {});
}

void Scanner::EnqueueScanTasks(const std::filesystem::path& root_path) {
  file_enumerator_.Enumerate(
      root_path,
      [this](const std::filesystem::path& file_path) {
        thread_pool_.Add(
            [this, file_path]() { this->ProcessFile(file_path); });
      },
      [this](const std::filesystem::path& path, const std::string& message) {
        errors_.fetch_add(1);
        logger_.Log(ILogger::Level::Error, path.string() + ": " + message);
      });
}

void Scanner::ProcessFile(const std::filesystem::path& file_path) {
  try {
    const auto hash_opt = hash_compute_->ComputeFileHash(file_path);

    if (!hash_opt.has_value()) {
      errors_.fetch_add(1);
      logger_.Log(ILogger::Level::Error,
                  "ОШИБКА: не удалось вычислить хеш для файла: " +
                      file_path.string());
      return;
    }

    const std::string& hash = hash_opt.value();

    const auto verdict = hash_database_.GetVerdict(hash);

    if (verdict.has_value()) {
      malicious_files_.fetch_add(1);
      LogMaliciousFile(file_path, hash, *verdict);
                                                                         
                                                                         
      MaliciousCallback callback;
      {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        callback = malicious_callback_;
      }
      if (callback) {
        callback(file_path, hash, *verdict);
      }
    }

    total_files_.fetch_add(1);

  } catch (const std::exception& e) {
    errors_.fetch_add(1);
    logger_.Log(ILogger::Level::Error,
                "ИСКЛЮЧЕНИЕ при обработке файла " + file_path.string() + ": " +
                    e.what());
  } catch (...) {
    errors_.fetch_add(1);
    logger_.Log(ILogger::Level::Error,
                "НЕИЗВЕСТНОЕ ИСКЛЮЧЕНИЕ при обработке файла: " +
                    file_path.string());
  }
}

void Scanner::LogMaliciousFile(const std::filesystem::path& file_path,
                               std::string_view hash,
                               std::string_view verdict) {
  const std::string message =
      "ВРЕДОНОСНЫЙ ФАЙЛ ОБНАРУЖЕН:\n   Путь: " + file_path.string() + "\n   " +
      std::string(hash_compute_->AlgorithmName()) + ": " + std::string(hash) +
      "\n   Тип:  " + std::string(verdict);
  logger_.Log(ILogger::Level::Warning, message);
}

Scanner::ScanResult Scanner::GetCurrentStats() const noexcept {
  return ScanResult{.total_files = total_files_.load(),
                    .total_expected_files = total_expected_files_.load(),
                    .malicious_files = malicious_files_.load(),
                    .errors = errors_.load(),
                    .duration = std::chrono::milliseconds(0)};
}
