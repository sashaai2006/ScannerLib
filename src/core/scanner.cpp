#include "core/scanner.hpp"

#include "utils/logger.hpp"
#include "utils/validate_path.hpp"

#include <stdexcept>
#include <thread>
#include <utility>

Scanner::Scanner(const std::string& csv_path,
                 const std::string& log_path,
                 size_t thread_count) {
  if (thread_count == 0) {
    thread_count = DEFAULT_THREAD_COUNT;
  }
  thread_count_ = thread_count;
  csv_path_ = csv_path;
  log_path_ = log_path;

  PathChecker::ValidatePaths(csv_path, log_path, "");

  Logger::Instance().Init(log_path);

  hash_base_ = std::make_unique<HashBase>();
  hash_base_->LoadHashes(csv_path);

  md5_compute_ = std::make_unique<MD5Compute>();

  thread_pool_ =
      std::make_unique<ThreadPool<std::function<void()>>>(thread_count_);

  Logger::Instance().Log(Logger::Level::Info,
                         "=== НОВАЯ СЕССИЯ СКАНИРОВАНИЯ НАЧАТА ===");
  Logger::Instance().Log(
      Logger::Level::Info,
      "Количество рабочих потоков: " + std::to_string(thread_count_));
}

Scanner::~Scanner() noexcept {
  try {
    Logger::Instance().Log(Logger::Level::Info,
                           "=== СЕССИЯ СКАНИРОВАНИЯ ЗАВЕРШЕНА ===");
  } catch (...) {
  }
}

void Scanner::SetMaliciousCallback(MaliciousCallback callback) {
  malicious_callback_ = std::move(callback);
}

Scanner::ScanResult Scanner::Scan(const std::filesystem::path& root_path) {
  auto start_time = std::chrono::steady_clock::now();

  total_files_.store(0);
  total_expected_files_.store(0);
  malicious_files_.store(0);
  errors_.store(0);

  try {
    PathChecker::ValidatePaths(csv_path_, log_path_, root_path.string());

    Logger::Instance().Log(
        Logger::Level::Info,
        "Начинаем сканирование директории: " + root_path.string());

    CountFiles(root_path);
    EnqueueScanTasks(root_path);

    thread_pool_->Wait();

  } catch (const std::exception& e) {
    Logger::Instance().Log(Logger::Level::Error,
                           std::string("ОШИБКА при сканировании: ") + e.what());
    throw;
  }

  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  ScanResult result{.total_files = total_files_.load(),
                    .total_expected_files = total_expected_files_.load(),
                    .malicious_files = malicious_files_.load(),
                    .errors = errors_.load(),
                    .duration = duration};

  Logger::Instance().Log(Logger::Level::Info,
                         "=== СТАТИСТИКА СКАНИРОВАНИЯ ===");
  Logger::Instance().Log(
      Logger::Level::Info,
      "Всего файлов обработано: " + std::to_string(result.total_files));
  Logger::Instance().Log(
      Logger::Level::Info,
      "Вредоносных файлов найдено: " + std::to_string(result.malicious_files));
  Logger::Instance().Log(Logger::Level::Info,
                         "Ошибок обработки: " + std::to_string(result.errors));
  Logger::Instance().Log(
      Logger::Level::Info,
      "Время выполнения: " + std::to_string(duration.count()) + " мс");

  return result;
}

void Scanner::CountFiles(const std::filesystem::path& root_path) {
  try {
    std::error_code ec;
    std::filesystem::recursive_directory_iterator iter(
        root_path,
        std::filesystem::directory_options::skip_permission_denied,
        ec);

    if (ec) {
      return;
    }

    while (iter != std::filesystem::recursive_directory_iterator()) {
      try {
        const auto& entry = *iter;

        if (entry.is_regular_file(ec) && !ec) {
          total_expected_files_.fetch_add(1);
        } else if (entry.is_directory(ec) && ec) {
          iter.disable_recursion_pending();
          ec.clear();
        } else if (ec) {
          ec.clear();
        }
      } catch (const std::filesystem::filesystem_error&) {
        iter.disable_recursion_pending();
      }

      std::error_code inc_ec;
      iter.increment(inc_ec);
      if (inc_ec) {
        break;
      }
    }
  } catch (const std::filesystem::filesystem_error&) {
  }
}

void Scanner::EnqueueScanTasks(const std::filesystem::path& root_path) {
  try {
    std::error_code ec;

    std::filesystem::recursive_directory_iterator iter(
        root_path,
        std::filesystem::directory_options::skip_permission_denied,
        ec);

    if (ec) {
      errors_.fetch_add(1);
      Logger::Instance().Log(
          Logger::Level::Error,
          "ОШИБКА открытия директории " + root_path.string() +
              " для обхода: " + ec.message());
      return;
    }

    while (iter != std::filesystem::recursive_directory_iterator()) {
      try {
        const auto& entry = *iter;

        if (entry.is_directory(ec)) {
          if (ec) {
            errors_.fetch_add(1);
            Logger::Instance().Log(
                Logger::Level::Error,
                "ОШИБКА проверки директории " + entry.path().string() +
                    ": " + ec.message() + ", пропускаем вложенные файлы");
            iter.disable_recursion_pending();
            ec.clear();
          } else {
            // Проверяем, можно ли читать содержимое директории, прежде чем
            // разрешать рекурсивный обход.
            std::error_code access_ec;
            auto test_iter =
                std::filesystem::directory_iterator(entry.path(), access_ec);

            if (access_ec) {
              errors_.fetch_add(1);
              Logger::Instance().Log(
                  Logger::Level::Warning,
                  "Нет прав доступа к директории " + entry.path().string() +
                      " (" + access_ec.message() +
                      "), пропускаем рекурсивный обход");
              iter.disable_recursion_pending();
            }
          }
        } else if (entry.is_regular_file(ec) && !ec) {
          auto task = [this, file_path = entry.path()]() {
            this->ProcessFile(file_path);
          };

          thread_pool_->Add(std::move(task));
        } else if (ec) {
          errors_.fetch_add(1);
          Logger::Instance().Log(
              Logger::Level::Error,
              "ОШИБКА проверки элемента " + entry.path().string() +
                  ": " + ec.message());
          ec.clear();
        }
      } catch (const std::filesystem::filesystem_error& e) {
        errors_.fetch_add(1);
        Logger::Instance().Log(
            Logger::Level::Error,
            "ОШИБКА файловой системы при обработке элемента в директории " +
                root_path.string() + ": " + e.what() + ", продолжаем обход");
        iter.disable_recursion_pending();
      }

      std::error_code inc_ec;
      iter.increment(inc_ec);
      if (inc_ec) {
        errors_.fetch_add(1);
        Logger::Instance().Log(
            Logger::Level::Error,
            "ОШИБКА перехода к следующему элементу в директории " +
                root_path.string() + ": " + inc_ec.message());
        break;
      }
    }

  } catch (const std::filesystem::filesystem_error& e) {
    errors_.fetch_add(1);
    Logger::Instance().Log(
        Logger::Level::Error,
        "Критическая ошибка при сканировании директории " +
            root_path.string() + ": " + e.what());
  }
}

void Scanner::ProcessFile(const std::filesystem::path& file_path) {
  try {
    auto hash_opt = md5_compute_->ComputeFileHashMD5(file_path);

    if (!hash_opt.has_value()) {
      errors_.fetch_add(1);
      Logger::Instance().Log(
          Logger::Level::Error,
          "ОШИБКА: не удалось вычислить MD5 для файла: " + file_path.string());
      return;
    }

    std::string hash = hash_opt.value();

    const std::string* verdict = hash_base_->GetVerdict(hash);

    if (verdict != nullptr) {
      malicious_files_.fetch_add(1);
      LogMaliciousFile(file_path, hash, *verdict);
      if (malicious_callback_) {
        malicious_callback_(file_path, hash, *verdict);
      }
    }

    total_files_.fetch_add(1);

  } catch (const std::exception& e) {
    errors_.fetch_add(1);
    Logger::Instance().Log(Logger::Level::Error,
                           "ИСКЛЮЧЕНИЕ при обработке файла " +
                               file_path.string() + ": " + e.what());
  } catch (...) {
    errors_.fetch_add(1);
    Logger::Instance().Log(
        Logger::Level::Error,
        "НЕИЗВЕСТНОЕ ИСКЛЮЧЕНИЕ при обработке файла: " + file_path.string());
  }
}

void Scanner::LogMaliciousFile(const std::filesystem::path& file_path,
                               const std::string& hash,
                               const std::string& verdict) {
  Logger::Instance().Log(
      Logger::Level::Warning,
      "ВРЕДОНОСНЫЙ ФАЙЛ ОБНАРУЖЕН:\n   Путь: " + file_path.string() +
          "\n   MD5:  " + hash + "\n   Тип:  " + verdict);
}

Scanner::ScanResult Scanner::GetCurrentStats() const noexcept {
  return ScanResult{.total_files = total_files_.load(),
                    .total_expected_files = total_expected_files_.load(),
                    .malicious_files = malicious_files_.load(),
                    .errors = errors_.load(),
                    .duration = std::chrono::milliseconds(0)};
}
