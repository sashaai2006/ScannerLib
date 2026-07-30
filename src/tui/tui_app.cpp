#include "tui/tui_app.hpp"

#include "core/scan_controller.hpp"
#include "crypto/hash_compute_factory.hpp"
#include "tui/cli_options.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

int TuiApp::Run(int argc, char* argv[]) {
  std::string base_str;
  std::string log_str;
  std::string path_str;
  std::string threads_str = "4";
  std::string algo_str = "SHA256";

  try {
    const auto parsed = CliOptions::Parse(argc, argv);
    if (!parsed.has_value()) {
      std::cerr << CliOptions::Usage(argv[0]);
      return 0;
    }
    base_str = parsed->base_path;
    log_str = parsed->log_path;
    path_str = parsed->scan_path;
    threads_str = parsed->threads;
    algo_str = parsed->algorithm;
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n" << CliOptions::Usage(argv[0]);
    return 1;
  }

  using namespace ftxui;

  ScanController controller;

  std::atomic<bool> has_error{false};
  std::string error_message;
  std::mutex error_mutex;

  int selected_tab = 0;

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
      size_t pos = 0;
      threads = std::stoul(threads_str, &pos);
                                                                         
      constexpr size_t kMaxThreads = 256;
      if (pos != threads_str.size() || threads == 0 || threads > kMaxThreads) {
        error_message = "Число потоков должно быть от 1 до 256";
        has_error = true;
        return;
      }
    } catch (...) {
      error_message = "Некорректное число потоков";
      has_error = true;
      return;
    }

    ScanConfig config;
    config.csv_path = base_str;
    config.log_path = log_str;
    config.scan_path = path_str;
    config.thread_count = threads;
    config.algorithm = algo_names[selected_algo];

    if (!controller.Start(config)) {
      error_message = controller.GetErrorMessage();
      has_error = true;
      return;
    }

    selected_tab = 1;
  };

  auto base_input = Input(&base_str, "путь к CSV-базе");
  auto log_input = Input(&log_str, "путь к файлу лога");
  auto path_input = Input(&path_str, "директория для сканирования");
  auto threads_input = Input(&threads_str, "количество потоков");
  auto algo_dropdown = Dropdown(&algo_labels, &selected_algo);
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
    const auto stats = controller.GetStats();
    const auto elapsed = controller.GetElapsed();
    const auto threats = controller.GetThreats();
    const bool done = controller.IsDone();

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
        const double files_per_ms = static_cast<double>(stats.total_files) /
                                    static_cast<double>(elapsed.count());
        const int files_per_s = static_cast<int>(files_per_ms * 1000.0);
        speed_text = std::to_string(files_per_s) + " файлов/с";

        const size_t remaining = stats.total_expected_files - stats.total_files;
        const double eta_ms = static_cast<double>(remaining) / files_per_ms;
        const int eta_s = static_cast<int>(eta_ms / 1000.0);
        eta_text = "Осталось: ~" + std::to_string(eta_s) + " с";
      } else {
        eta_text = "Осталось: вычисление...";
      }
    }

    Elements threat_elements;
    for (const auto& record : threats) {
      threat_elements.push_back(hbox(
          {text(record.path) | flex, separator(),
           text(record.verdict) | color(Color::RedLight)}));
    }
    if (threat_elements.empty()) {
      threat_elements.push_back(text("—"));
    }

    std::string scan_status;
    Color status_color = Color::Yellow;
    if (controller.HasError()) {
      scan_status = controller.GetErrorMessage();
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

                                                                          
                                                                          
                                                               
  std::atomic<bool> ui_running{true};
  std::thread refresh_thread([&]() {
    while (ui_running.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      screen.Post(Event::Custom);
    }
  });

  auto app = CatchEvent(tabs, [&](Event event) {
    if (event == Event::Character('q')) {
      screen.Exit();
      return true;
    }
    return false;
  });

  screen.Loop(app);

  ui_running.store(false);
  refresh_thread.join();
  controller.Wait();

  if (controller.HasError()) {
    return 1;
  }
  if (controller.GetStats().errors > 0) {
    return 2;
  }
  return 0;
}
