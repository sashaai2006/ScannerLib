#include "tui/cli_options.hpp"

#include <getopt.h>

#include <stdexcept>

std::string CliOptions::Usage(const char* program_name) {
  return std::string("Usage: ") + program_name +
         " [--base <csv>] [--log <log>] [--path <dir>] [--threads <num>] "
         "[--algo <md5|sha1|sha256>]\n";
}

std::optional<CliOptions> CliOptions::Parse(int argc, char* argv[]) {
  CliOptions options;

  const option long_options[] = {
      {"base", required_argument, nullptr, 'b'},
      {"log", required_argument, nullptr, 'l'},
      {"path", required_argument, nullptr, 'p'},
      {"threads", required_argument, nullptr, 't'},
      {"algo", required_argument, nullptr, 'a'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0}};

  while (true) {
    int option_index = 0;
    const int c =
        getopt_long(argc, argv, "b:l:p:t:a:h", long_options, &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
      case 'b':
        options.base_path = optarg;
        break;
      case 'l':
        options.log_path = optarg;
        break;
      case 'p':
        options.scan_path = optarg;
        break;
      case 't':
        options.threads = optarg;
        break;
      case 'a':
        options.algorithm = optarg;
        break;
      case 'h':
        return std::nullopt;
      default:
        throw std::invalid_argument("неизвестный аргумент командной строки");
    }
  }

  return options;
}
