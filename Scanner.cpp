#include "Scanner.h"
#include "ValidatePath.h"
#include <iostream>
#include <iomanip>

Scanner::Scanner(const std::string& csv_path,
                const std::string& log_path,
                size_t thread_count) {

    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) {
            thread_count = DEFAULT_THREAD_COUNT;
        }
    }

    PathChecker::validate_paths(csv_path, log_path, "");

    hash_base_ = std::make_unique<HashBase>();
    hash_base_->load_hashes(csv_path);

    md5_compute_ = std::make_unique<MD5Compute>();

    thread_pool_ = std::make_unique<ThreadPool<std::function<void()>>>(thread_count);

    log_file_.open(log_path, std::ios::out | std::ios::app);
    if (!log_file_.is_open()) {
        throw std::runtime_error("Не удается открыть файл лога: " + log_path);
    }

    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);

        log_file_ << "\n=== НОВАЯ СЕССИЯ СКАНИРОВАНИЯ НАЧАТА " 
                  << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S") 
                  << " ===" << std::endl;
        log_file_ << "Количество рабочих потоков: " << thread_count << std::endl;
        log_file_.flush();
    }
}


Scanner::~Scanner() noexcept {
    try {
        if (log_file_.is_open()) {
            std::lock_guard<std::mutex> lock(log_mutex_);
            log_file_ << "=== СЕССИЯ СКАНИРОВАНИЯ ЗАВЕРШЕНА ===" << std::endl;
            log_file_.close();
        }
        
    } catch (...) {
    }
}

Scanner::ScanResult Scanner::Scan(const std::filesystem::path& root_path) {
    auto start_time = std::chrono::steady_clock::now();
    
    try {
        if (!std::filesystem::exists(root_path)) {
    throw std::runtime_error("Директория для сканирования не найдена: " + root_path.string());
        }
        if (!std::filesystem::is_directory(root_path)) {
            throw std::runtime_error("Указанный путь не является директорией: " + root_path.string());
        }
        
        {
            std::lock_guard<std::mutex> lock(log_mutex_);
            log_file_ << "Начинаем сканирование директории: " << root_path << std::endl;
            log_file_.flush();
        }
        
        enqueue_scan_tasks(root_path);
        
        thread_pool_.reset();
        
        thread_pool_ = std::make_unique<ThreadPool<std::function<void()>>>(DEFAULT_THREAD_COUNT);
        
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_file_ << "ОШИБКА при сканировании: " << e.what() << std::endl;
        throw;
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    ScanResult result{
        .total_files = total_files_.load(),
        .malicious_files = malicious_files_.load(), 
        .errors = errors_.load(),
        .duration = duration
    };
    
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_file_ << "\n=== СТАТИСТИКА СКАНИРОВАНИЯ ===" << std::endl;
        log_file_ << "Всего файлов обработано: " << result.total_files << std::endl;
        log_file_ << "Вредоносных файлов найдено: " << result.malicious_files << std::endl;
        log_file_ << "Ошибок обработки: " << result.errors << std::endl;
        log_file_ << "Время выполнения: " << duration.count() << " мс" << std::endl;
        log_file_.flush();
    }
    
    return result;
}

void Scanner::enqueue_scan_tasks(const std::filesystem::path& root_path) {
    try {
        std::error_code ec;
        
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root_path, ec)) {
            if (ec) {
                errors_.fetch_add(1);
                std::lock_guard<std::mutex> lock(log_mutex_);
                log_file_ << "ОШИБКА при обходе директории: " << ec.message() << std::endl;
                continue;
            }
            
            if (entry.is_regular_file(ec) && !ec) {
                auto task = [this, file_path = entry.path()]() {
                    this->process_file(file_path);
                };
                
                thread_pool_->Add(std::move(task));
            }
        }
        
    } catch (const std::filesystem::filesystem_error& e) {
        throw std::runtime_error("Ошибка при сканировании директории " + 
                                root_path.string() + ": " + e.what());
    }
}

void Scanner::process_file(const std::filesystem::path& file_path) {
    try {
        auto hash_opt = md5_compute_->computeFileHashMD5(file_path);
        
        if (!hash_opt.has_value()) {
            errors_.fetch_add(1);
            
            std::lock_guard<std::mutex> lock(log_mutex_);
            log_file_ << "ОШИБКА: не удалось вычислить MD5 для файла: " << file_path << std::endl;
            return;
        }
        
        std::string hash = hash_opt.value();
        
        const std::string* verdict = hash_base_->get_verdict(hash);
        
        if (verdict != nullptr) {
            malicious_files_.fetch_add(1);
            log_malicious_file(file_path, hash, *verdict);
        }
        
        total_files_.fetch_add(1);
        
    } catch (const std::exception& e) {
        errors_.fetch_add(1);
        
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_file_ << "ИСКЛЮЧЕНИЕ при обработке файла " << file_path 
                 << ": " << e.what() << std::endl;
    } catch (...) {
        errors_.fetch_add(1);
        
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_file_ << "НЕИЗВЕСТНОЕ ИСКЛЮЧЕНИЕ при обработке файла: " << file_path << std::endl;
    }
}

void Scanner::log_malicious_file(const std::filesystem::path& file_path, 
                                 const std::string& hash, 
                                 const std::string& verdict) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    log_file_ << " ВРЕДОНОСНЫЙ ФАЙЛ ОБНАРУЖЕН:" << std::endl;
    log_file_ << "   Путь: " << file_path << std::endl;
    log_file_ << "   MD5:  " << hash << std::endl;
    log_file_ << "   Тип:  " << verdict << std::endl;
    log_file_ << "   ---" << std::endl;
    
    log_file_.flush();
}

Scanner::ScanResult Scanner::GetCurrentStats() const noexcept {
    return ScanResult{
        .total_files = total_files_.load(),
        .malicious_files = malicious_files_.load(),
        .errors = errors_.load(),
        .duration = std::chrono::milliseconds(0)
    };
}
