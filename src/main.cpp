#include <getopt.h>
#include <chrono>
#include <string>
#include <thread>

#include "core/scanner.hpp"
#include "utils/logger.hpp"

void PrintUsage(const char* program_name) {
  Logger::Instance().Info(
      std::string("Usage: ") + program_name +
      " [options]\n"
      "  --base <file>    Base CSV file path (required)\n"
      "  --log <file>     Log file path (required)\n"
      "  --path <dir>     Directory to scan (required)\n"
      "  --threads <num>  Number of threads (default: auto)\n"
      "  -h, --help       Show help");
}

int main(int argc, char* argv[]) {
  std::string base_file, log_file, scan_path;
  size_t threads = 0;

  const option long_options[] = {{"base", required_argument, nullptr, 'b'},
                                 {"log", required_argument, nullptr, 'l'},
                                 {"path", required_argument, nullptr, 'p'},
                                 {"threads", required_argument, nullptr, 't'},
                                 {"help", no_argument, nullptr, 'h'},
                                 {nullptr, 0, nullptr, 0}};

  while (true) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "b:l:p:t:h", long_options, &option_index);
    if (c == -1)
      break;
    switch (c) {
      case 'b':
        base_file = optarg;
        break;
      case 'l':
        log_file = optarg;
        break;
      case 'p':
        scan_path = optarg;
        break;
      case 't':
        threads = std::stoul(optarg);
        break;
      case 'h':
        PrintUsage(argv[0]);
        return 0;
      default:
        PrintUsage(argv[0]);
        return 1;
    }
  }

  if (base_file.empty() || log_file.empty() || scan_path.empty()) {
    Logger::Instance().Error("Error: --base, --log, and --path are required.");
    PrintUsage(argv[0]);
    return 1;
  }

  if (threads == 0) {
    threads = std::thread::hardware_concurrency();
    if (threads == 0)
      threads = 4;
  }

  try {
    Logger::Instance().Info("=== Scanner Started ===");
    Logger::Instance().Info("Base file: " + base_file);
    Logger::Instance().Info("Log file: " + log_file);
    Logger::Instance().Info("Scanning path: " + scan_path);
    Logger::Instance().Info("Threads: " + std::to_string(threads));

    Scanner scanner(base_file, log_file, threads);

    auto result = scanner.Scan(scan_path);

    Logger::Instance().Info("=== Scan Report ===");
    Logger::Instance().Info("Total files processed: " +
                            std::to_string(result.total_files));
    Logger::Instance().Info("Malicious files found: " +
                            std::to_string(result.malicious_files));
    Logger::Instance().Info("Processing errors: " +
                            std::to_string(result.errors));
    Logger::Instance().Info("Execution time (ms): " +
                            std::to_string(result.duration.count()));
    Logger::Instance().Info("====================");

    return (result.errors > 0) ? 2 : 0;
  } catch (const std::exception& e) {
    Logger::Instance().Error(std::string("Error: ") + e.what());
    return 1;
  } catch (...) {
    Logger::Instance().Error("Unknown error occurred.");
    return 1;
  }
}
