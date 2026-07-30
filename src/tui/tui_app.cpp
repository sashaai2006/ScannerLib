#include "tui/tui_app.hpp"

#include "core/scanner.hpp"
#include "crypto/hash_compute_factory.hpp"
#include "utils/logger.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct MaliciousRecord {
  std::string path;
  std::string verdict;
};

int TuiApp::Run(int argc, char* argv[]) {
  std::string base_str;
  std::string log_str;
  std::string path_str;
  std::string threads_str = "4";
  std::string algo_str = "SHA256";

  const option long_options[] = {
      {"base", required_argument, nullptr, 'b'},
      {"log", required_argument, nullptr, 'l'},
      {"path", required_argument, nullptr, 'p'},
      {"threads", required_argument, nullptr, 't'},
      {"algo", required_argument, nullptr, 'a'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0}};

  try {
    while (true) {
      int option_index = 0;
      int c = getopt_long(argc, argv, "b:l:p:t:a:h", long_options, &option_index);
      if (c == -1) break;
      switch (c) {
        case 'b': base_str = optarg; break;
        case 'l': log_str = optarg; break;
        case 'p': path_str = optarg; break;
        case 't': threads_str = optarg; break;
        case 'a': algo_str = optarg; break;
        case 'h':
          std::cerr << "Usage: " << argv[0]
                    << " [--base <csv>] [--log <log>] [--path <dir>] "
                       "[--threads <num>] [--algo <md5|sha1|sha256>]\n";
          return 0;
        default:
          std::cerr << "Usage: " << argv[0]
                    << " [--base <csv>] [--log <log>] [--path <dir>] "
                       "[--threads <num>] [--algo <md5|sha1|sha256>]\n";
          return 1;
      }
    }
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  using namespace ftxui;

  std::unique_ptr<Scanner> scanner;
  std::thread scan_thread;

  std::string error_message;
  std::mutex error_mutex;
  std::atomic<bool> has_error{false};

  int selected_tab = 0;
  std::atomic<bool> done{true};
  Scanner::ScanResult result{0, 0, 0, 0, std::chrono::milliseconds{0}};

  std::vector<std::string> algo_names;
  std::vector<std::string> algo_labels;
  int selected_algo = 0;
  for (const auto& info : HashComputeFactory::AvailableAlgorithms()) {
    if (info.name == algo_str) {
      selected_algo = static_cast<int>(algo_names.size());
    }
    algo_names.push_back(info.name);
    algo_labels.push_back(info.name + (info.deprecated ? " (устарел)" : ""));
  }
  if (algo_names.empty()) {
    algo_names.push_back("SHA256");
    algo_labels.push_back("SHA256");
  }

  std::vector<MaliciousRecord> threats;
  std::mutex threats_mutex;

  std::chrono::steady_clock::time_point start_time;

  auto base_input = Input(&base_str, "путь к CSV-базе");
  auto log_input = Input(&log_str, "путь к файлу лога");
  auto path_input = Input(&path_str, "директория для сканирования");
  auto threads_input = Input(&threads_str, "количество потоков");
  auto algo_dropdown = Dropdown(&algo_labels, &selected_algo);

  auto start_scan = [&]() {
    std::lock_guard<std::mutex> lock(error_mutex);
    error_message.clear();
    has_error = false;

    if (base_str.empty() || log_str.empty() || path_str.empty()) {
      error_message = "Заполните все обязательные поля";
      has_error = true;
      return;
    }

    size_t threads = 4;
    try {
      threads = std::stoul(threads_str);
    } catch (...) {
      error_message = "Некорректное число потоков";
      has_error = true;
      return;
    }

    const std::string& selected_algo_name = algo_names[selected_algo];
    if (!HashComputeFactory::IsSupported(selected_algo_name)) {
      error_message = "Неподдерживаемый алгоритм хеширования";
      has_error = true;
      return;
    }

    try {
      scanner = std::make_unique<Scanner>(base_str, log_str, threads,
                                          selected_algo_name);
    } catch (const std::exception& e) {
      error_message = std::string("Ошибка: ") + e.what();
      has_error = true;
      return;
    }

    scanner->SetMaliciousCallback(
        [&](const std::filesystem::path& file_path,
            const std::string& /*hash*/,
            const std::string& verdict) {
          std::lock_guard<std::mutex> lock(threats_mutex);
          threats.push_back({file_path.string(), verdict});
        });

    {
      std::lock_guard<std::mutex> lock(threats_mutex);
      threats.clear();
    }

    start_time = std::chrono::steady_clock::now();
    done = false;

    if (scan_thread.joinable()) {
      scan_thread.join();
    }

    scan_thread = std::thread([&]() {
      try {
        result = scanner->Scan(path_str);
      } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(error_mutex);
        error_message = std::string("Ошибка сканирования: ") + e.what();
        has_error = true;
      }
      done = true;
    });

    selected_tab = 1;
  };

  auto start_button = Button("Начать сканирование", start_scan);

  auto input_tab = Container::Vertical(
      {base_input, log_input, path_input, threads_input, algo_dropdown,
       start_button});

  auto error_element = Renderer([&]() {
    std::lock_guard<std::mutex> lock(error_mutex);
    if (!has_error || error_message.empty()) {
      return text(" ");
    }
    return text(error_message) | color(Color::RedLight) | center;
  });

  auto form_screen = Renderer(input_tab, [&]() {
    return vbox({
        text("ScannerLib") | bold | center,
        separator(),
        hbox({
            filler(),
            vbox({
                hbox({text("База:   ") | size(WIDTH, EQUAL, 8), base_input->Render()}),
                hbox({text("Лог:    ") | size(WIDTH, EQUAL, 8), log_input->Render()}),
                hbox({text("Путь:   ") | size(WIDTH, EQUAL, 8), path_input->Render()}),
                hbox({text("Потоки: ") | size(WIDTH, EQUAL, 8), threads_input->Render()}),
                hbox({text("Алгоритм:") | size(WIDTH, EQUAL, 8), algo_dropdown->Render()}),
                separator(),
                start_button->Render() | center,
            }) | border | size(WIDTH, GREATER_THAN, 60),
            filler(),
        }) | flex,
        error_element->Render(),
        text("Tab/стрелки — навигация  |  Enter — начать сканирование  |  q — выход")
            | center | dim,
    });
  });

  form_screen = CatchEvent(form_screen, [&](Event event) {
    if (event == Event::Return) {
      start_scan();
      return true;
    }
    return false;
  });

  auto scan_tab = Renderer([&]() {
    Scanner::ScanResult stats = scanner ? scanner->GetCurrentStats()
                                        : Scanner::ScanResult{0, 0, 0, 0,
                                                              std::chrono::milliseconds{0}};
    if (done) {
      stats = result;
    }

    std::chrono::milliseconds elapsed{0};
    if (!done) {
      elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - start_time);
    } else if (!has_error) {
      elapsed = result.duration;
    }

    double ratio = 0.0;
    std::string speed_text;
    std::string eta_text;
    if (stats.total_expected_files > 0) {
      ratio = static_cast<double>(stats.total_files) /
              static_cast<double>(stats.total_expected_files);
      if (ratio > 1.0) {
        ratio = 1.0;
      }

      if (elapsed.count() > 0 && stats.total_files > 0) {
        double files_per_ms = static_cast<double>(stats.total_files) /
                              static_cast<double>(elapsed.count());
        int files_per_s = static_cast<int>(files_per_ms * 1000.0);
        speed_text = std::to_string(files_per_s) + " файлов/с";

        size_t remaining = stats.total_expected_files - stats.total_files;
        double eta_ms = static_cast<double>(remaining) / files_per_ms;
        int eta_s = static_cast<int>(eta_ms / 1000.0);
        eta_text = "Осталось: ~" + std::to_string(eta_s) + " с";
      } else {
        eta_text = "Осталось: вычисление...";
      }
    }

    Elements threat_elements;
    {
      std::lock_guard<std::mutex> lock(threats_mutex);
      for (const auto& record : threats) {
        threat_elements.push_back(hbox(
            {text(record.path) | flex, separator(),
             text(record.verdict) | color(Color::RedLight)}));
      }
    }
    if (threat_elements.empty()) {
      threat_elements.push_back(text("—"));
    }

    std::string scan_status;
    Color status_color = Color::Yellow;
    {
      std::lock_guard<std::mutex> lock(error_mutex);
      if (has_error) {
        scan_status = error_message;
        status_color = Color::RedLight;
      } else if (done) {
        scan_status = "Сканирование завершено за " +
                      std::to_string(elapsed.count()) + " мс";
        status_color = Color::Green;
      } else if (stats.total_expected_files == 0) {
        scan_status = "Подсчёт файлов...";
      } else {
        scan_status = "Сканирование: " + std::to_string(stats.total_files) +
                      " / " + std::to_string(stats.total_expected_files);
      }
    }

    return vbox({
        text("ScannerLib") | bold | center,
        separator(),
        hbox({
            vbox({
                text("Обработано: " + std::to_string(stats.total_files)),
                text("Всего:      " + std::to_string(stats.total_expected_files)),
                text("Угроз:      " + std::to_string(stats.malicious_files)),
                text("Ошибок:     " + std::to_string(stats.errors)),
                text("Время:      " + std::to_string(elapsed.count()) + " мс"),
            }) | flex,
            vbox({
                text(base_str) | color(Color::Cyan),
                text(log_str) | color(Color::Cyan),
                text(path_str) | color(Color::Cyan),
            }) | flex,
        }),
        separator(),
        hbox({
            text("Прогресс") | flex,
            text(speed_text) | dim,
        }),
        hbox({
            gauge(ratio) | flex,
            text(" " + std::to_string(static_cast<int>(ratio * 100.0)) + "%"),
        }),
        text(eta_text) | dim,
        separator(),
        text("Найденные угрозы:") | bold,
        vbox(threat_elements) | frame | flex | border,
        separator(),
        hbox({
            text(scan_status) | color(status_color) | flex,
            text("q — выход") | dim,
        }),
    });
  });

  auto tabs = Container::Tab({form_screen, scan_tab}, &selected_tab);

  auto screen = ScreenInteractive::Fullscreen();

  std::thread refresh_thread([&]() {
    while (!done) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      screen.Post(Event::Custom);
    }
    screen.Post(Event::Custom);
  });

  auto app = CatchEvent(tabs, [&](Event event) {
    if (event == Event::Character('q')) {
      screen.Exit();
      return true;
    }
    return false;
  });

  screen.Loop(app);

  done = true;
  refresh_thread.join();
  if (scan_thread.joinable()) {
    scan_thread.join();
  }

  if (has_error) {
    return 1;
  }
  if (result.errors > 0) {
    return 2;
  }
  return 0;
}
