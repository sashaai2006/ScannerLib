#include "utils/validate_path.hpp"

#include <string>

namespace {

std::string MakePathError(std::string_view prefix,
                          std::string_view path,
                          std::string_view suffix = "") {
  std::string result(prefix);
  result += path;
  result += suffix;
  return result;
}

}  // namespace

void PathChecker::ValidatePaths(std::string_view csv_path,
                                std::string_view log_path,
                                std::string_view root_path) {
  namespace fs = std::filesystem;

  if (csv_path.empty()) {
    throw std::runtime_error("Путь к базе хешей не может быть пустым");
  }
  if (log_path.empty()) {
    throw std::runtime_error("Путь к файлу лога не может быть пустым");
  }

  std::error_code ec;
  auto base_status = fs::status(fs::path(csv_path), ec);

  if (ec) {
    if (ec == std::errc::no_such_file_or_directory) {
      throw std::runtime_error(
          MakePathError("Файл базы хешей не найден: ", csv_path));
    } else if (ec == std::errc::permission_denied) {
      throw std::runtime_error(
          MakePathError("Нет прав доступа к файлу базы хешей: ", csv_path));
    } else {
      throw std::runtime_error(
          MakePathError("Ошибка доступа к файлу базы хешей: ", csv_path,
                        " (" + ec.message() + ")"));
    }
  }

  if (!fs::is_regular_file(base_status)) {
    if (fs::is_directory(base_status)) {
      throw std::runtime_error(MakePathError(
          "Путь к базе хешей указывает на директорию, а не файл: ", csv_path));
    } else {
      throw std::runtime_error(MakePathError(
          "Путь к базе хешей не является обычным файлом: ", csv_path));
    }
  }

  std::ifstream test_base{std::string(csv_path)};
  if (!test_base.is_open()) {
    throw std::runtime_error(MakePathError(
        "Не удается открыть файл базы хешей для чтения: ", csv_path));
  }
  test_base.close();

  if (!root_path.empty()) {
    auto root_status = fs::status(fs::path(root_path), ec);

    if (ec) {
      if (ec == std::errc::no_such_file_or_directory) {
        throw std::runtime_error(MakePathError(
            "Директория для сканирования не найдена: ", root_path));
      } else if (ec == std::errc::permission_denied) {
        throw std::runtime_error(MakePathError(
            "Нет прав доступа к директории сканирования: ", root_path));
      } else {
        throw std::runtime_error(
            MakePathError("Ошибка доступа к директории сканирования: ",
                          root_path,
                          " (" + ec.message() + ")"));
      }
    }

    if (!fs::is_directory(root_status)) {
      throw std::runtime_error(MakePathError(
          "Указанный путь не является директорией: ", root_path));
    }

    try {
      auto test_iter = fs::directory_iterator(fs::path(root_path), ec);
      if (ec == std::errc::permission_denied) {
        throw std::runtime_error(MakePathError(
            "Нет прав на чтение директории сканирования: ", root_path));
      }
    } catch (const fs::filesystem_error&) {
    }
  }

  fs::path log_file_path{std::string(log_path)};
  fs::path log_dir = log_file_path.parent_path();

  if (log_file_path.empty() || !log_file_path.has_filename()) {
    throw std::runtime_error(
        MakePathError("Некорректный путь к файлу лога: ", log_path));
  }

  if (!log_dir.empty()) {
    auto log_dir_status = fs::status(log_dir, ec);

    if (ec && ec != std::errc::no_such_file_or_directory) {
      throw std::runtime_error(
          "Ошибка доступа к директории лога: " + log_dir.string() +
          " (" + ec.message() + ")");
    }

    if (!fs::exists(log_dir)) {
      if (!fs::create_directories(log_dir, ec)) {
        if (ec) {
          throw std::runtime_error(
              "Не удается создать директорию для лога: " + log_dir.string() +
              " (" + ec.message() + ")");
        } else {
          throw std::runtime_error(
              "Не удается создать директорию для лога: " + log_dir.string());
        }
      }
    } else if (!fs::is_directory(log_dir)) {
      throw std::runtime_error(
          "Путь к директории лога указывает на файл, а не директорию: " +
          log_dir.string());
    }
  }

  std::ofstream test_log{std::string(log_path), std::ios::app};
  if (!test_log.is_open()) {
    throw std::runtime_error(MakePathError(
        "Не удается открыть файл лога для записи: ", log_path));
  }
  test_log.close();
}

bool PathChecker::IsValidHashBase(std::string_view csv_path) {
  namespace fs = std::filesystem;
  std::error_code ec;
  auto status = fs::status(fs::path(csv_path), ec);
  return !ec && fs::is_regular_file(status);
}

bool PathChecker::IsValidLogPath(std::string_view log_path) {
  std::ofstream test_log(std::string(log_path), std::ios::app);
  return test_log.is_open();
}

bool PathChecker::IsValidScanDirectory(std::string_view root_path) {
  namespace fs = std::filesystem;
  std::error_code ec;
  auto status = fs::status(fs::path(root_path), ec);
  return !ec && fs::is_directory(status);
}

void PathChecker::EnsureLogDirectoryExists(std::string_view log_path) {
  namespace fs = std::filesystem;
  fs::path log_dir = fs::path(std::string(log_path)).parent_path();
  if (!log_dir.empty() && !fs::exists(log_dir)) {
    std::error_code ec;
    fs::create_directories(log_dir, ec);
    if (ec) {
      throw std::runtime_error(
          "Не удается создать директорию для лога: " + log_dir.string());
    }
  }
}
