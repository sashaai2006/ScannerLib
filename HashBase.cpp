// HashBase.cpp
#include "HashBase.h"

#include <fstream>
#include <sstream>
#include <cctype>
#include <stdexcept>
#include <string>      
#include <unordered_map>      
#include <mutex>

void HashBase::trim(std::string& s) {
    const char* ws = " \t\r\n";
    const auto from = s.find_first_not_of(ws);
    if (from == std::string::npos) { s.clear(); return; }
    const auto to = s.find_last_not_of(ws);
    s = s.substr(from, to - from + 1);
}
void HashBase::load_hashes(const std::string& csv_path) {
    std::ifstream file(csv_path);
    if (!file.is_open()) {
        throw std::runtime_error("Не удается открыть файл базы хешей: " + csv_path);
    }
    std::string line;
    size_t line_num = 0;
    while (std::getline(file, line)) {
        ++line_num;
        trim(line);

        if (line.empty()) {
            continue;
        }
        const auto pos = line.find(';');
        if (pos == std::string::npos) {

            continue;
        }
        std::string hash = line.substr(0, pos);
        std::string verdict = line.substr(pos + 1);
        trim(hash);
        trim(verdict);
        std::transform(hash.begin(), hash.end(), hash.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

        if (hash.empty() || verdict.empty()) {
            std::lock_guard<std::mutex> lock(log_mutex_);
            log_file_ << "Предупреждение: некорректная строка " << line_num
              << " в базе хешей: " << line << std::endl;
        }else{
            malicious_hashes_map_.emplace(std::move(hash), std::move(verdict));
        }
    }
}

const std::string* HashBase::get_verdict(const std::string& hash_hex_lower) const {
    std::string hash_lower = hash_hex_lower;
    std::transform(hash_lower.begin(), hash_lower.end(), hash_lower.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    
    auto it = malicious_hashes_map_.find(hash_lower);
    return (it == malicious_hashes_map_.end()) ? nullptr : &it->second;
}

