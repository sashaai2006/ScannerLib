#include "tui/batch_app.hpp"

#include "core/scan_controller.hpp"
#include "crypto/hash_compute_factory.hpp"

#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string EscapeJson(std::string_view value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const char c : value) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          constexpr char kHexDigits[] = "0123456789abcdef";
          const auto byte = static_cast<unsigned char>(c);
          out += "\\u00";
          out += kHexDigits[byte >> 4];
          out += kHexDigits[byte & 0x0F];
        } else {
          out += c;
        }
        break;
    }
  }
  return out;
}

std::string BuildReportJson(const ScanConfig& config,
                            const Scanner::ScanResult& stats,
                            const std::vector<MaliciousRecord>& threats) {
  std::string status = "ok";
  if (stats.cancelled) {
    status = "cancelled";
  } else if (stats.errors > 0) {
    status = "completed_with_errors";
  }

  std::string json;
  json += "{\n";
  json += "  \"status\": \"" + status + "\",\n";
  json += "  \"algorithm\": \"" + EscapeJson(config.algorithm) + "\",\n";
  json += "  \"scan_path\": \"" + EscapeJson(config.scan_path) + "\",\n";
  json += "  \"total_files\": " + std::to_string(stats.total_files) + ",\n";
  json += "  \"total_expected_files\": " +
          std::to_string(stats.total_expected_files) + ",\n";
  json +=
      "  \"malicious_files\": " + std::to_string(stats.malicious_files) + ",\n";
  json += "  \"errors\": " + std::to_string(stats.errors) + ",\n";
  json +=
      "  \"duration_ms\": " + std::to_string(stats.duration.count()) + ",\n";
  json += "  \"cancelled\": " + std::string(stats.cancelled ? "true" : "false") +
          ",\n";
  json += "  \"threats\": [\n";
  bool first = true;
  for (const auto& threat : threats) {
    if (!first) {
      json += ",";
    }
    first = false;
    json += "    {\"path\": \"" + EscapeJson(threat.path) +
            "\", \"verdict\": \"" + EscapeJson(threat.verdict) + "\"}\n";
  }
  json += "  ]\n";
  json += "}\n";
  return json;
}

}  

int BatchApp::Run(const CliOptions& options) {
  if (options.base_path.empty() || options.log_path.empty() ||
      options.scan_path.empty()) {
    std::cerr << "Error: для --batch нужны --base, --log и --path\n"
              << CliOptions::Usage("scannerlib");
    return 1;
  }

  if (!HashComputeFactory::IsSupported(options.algorithm)) {
    std::cerr << "Error: неподдерживаемый алгоритм: " << options.algorithm
              << "\n";
    return 1;
  }

  ScanConfig config;
  try {
    config.csv_path = options.base_path;
    config.log_path = options.log_path;
    config.scan_path = options.scan_path;
    config.thread_count = CliOptions::ParseThreadCount(options.threads);
    config.algorithm = HashComputeFactory::CanonicalName(options.algorithm);
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  ScanController controller;
  if (!controller.Start(config)) {
    std::cerr << "Error: " << controller.GetErrorMessage() << "\n";
    return 1;
  }
  controller.Wait();

  if (controller.HasError()) {
    std::cerr << "Error: " << controller.GetErrorMessage() << "\n";
    return 1;
  }

  const auto stats = controller.GetStats();
  const auto threats = controller.GetThreats();
  const std::string report = BuildReportJson(config, stats, threats);

  if (!options.report_path.empty()) {
    std::ofstream out(options.report_path);
    if (!out) {
      std::cerr << "Error: не удалось записать отчёт: " << options.report_path
                << "\n";
      return 1;
    }
    out << report;
  } else {
    std::cout << report;
  }

  if (stats.errors > 0) {
    return 2;
  }
  return 0;
}
