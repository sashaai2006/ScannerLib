#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <getopt.h>
#include <iomanip>
#include "Scanner.h"

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "  --base <file>    Base CSV file path (required)\n"
              << "  --log <file>     Log file path (required)\n"
              << "  --path <dir>     Directory to scan (required)\n"
              << "  --threads <num>  Number of threads (default: auto)\n"
              << "  -h, --help       Show help\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    std::string base_file, log_file, scan_path;
    size_t threads = 0;

    const option long_options[] = {
        {"base", required_argument, nullptr, 'b'},
        {"log", required_argument, nullptr, 'l'},
        {"path", required_argument, nullptr, 'p'},
        {"threads", required_argument, nullptr, 't'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    while (true) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "b:l:p:t:h", long_options, &option_index);
        if (c == -1) break;
        switch (c) {
            case 'b': base_file = optarg; break;
            case 'l': log_file = optarg; break;
            case 'p': scan_path = optarg; break;
            case 't': threads = std::stoul(optarg); break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (base_file.empty() || log_file.empty() || scan_path.empty()) {
        std::cerr << "Error: --base, --log, and --path are required.\n";
        print_usage(argv[0]);
        return 1;
    }

    if (threads == 0) {
        threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 4;
    }

    try {
        std::cout << "=== Scanner Started ===\n";
        std::cout << "Base file: " << base_file << "\n";
        std::cout << "Log file: " << log_file << "\n";
        std::cout << "Scanning path: " << scan_path << "\n";
        std::cout << "Threads: " << threads << "\n\n";

        Scanner scanner(base_file, log_file, threads);

        auto start = std::chrono::steady_clock::now();
        auto result = scanner.Scan(scan_path);
        auto end = std::chrono::steady_clock::now();

        std::cout << "\n=== Scan Report ===\n";
        std::cout << "Total files processed: " << result.total_files << "\n";
        std::cout << "Malicious files found: " << result.malicious_files << "\n";
        std::cout << "Processing errors: " << result.errors << "\n";
        std::cout << "Execution time (ms): " << result.duration.count() << "\n";
        std::cout << "====================\n";

        return (result.errors > 0) ? 2 : 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred.\n";
        return 1;
    }
}
