#include "tui/batch_app.hpp"
#include "tui/cli_options.hpp"
#include "tui/tui_app.hpp"

#include <iostream>

int main(int argc, char* argv[]) {
  try {
    const auto parsed = CliOptions::Parse(argc, argv);
    if (!parsed.has_value()) {
      std::cerr << CliOptions::Usage(argv[0]);
      return 0;
    }
    if (parsed->batch) {
      return BatchApp::Run(*parsed);
    }
    return TuiApp::Run(*parsed);
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n" << CliOptions::Usage(argv[0]);
    return 1;
  }
}
