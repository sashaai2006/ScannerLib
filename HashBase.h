#pragma once

#ifndef DLL_EXPORT
#  ifdef _WIN32
#    define DLL_EXPORT __declspec(dllexport)
#  else
#    define DLL_EXPORT
#  endif
#endif

#include <string>
#include <unordered_map>
#include <mutex>
#include <fstream> 

class DLL_EXPORT HashBase{
private:
    std::unordered_map<std::string, std::string> malicious_hashes_map_;
    std::mutex log_mutex_;
    std::ofstream log_file_;
private:
    static void trim(std::string& s);
public:
    void load_hashes(const std::string& csv_path);
    const std::string* get_verdict(const std::string& hash_hex_lower) const;

};


