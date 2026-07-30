#include "utils/path_validator.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace {

std::string MakePathError(std::string_view prefix,
                          std::string_view path,
                          std::string_view suffix = "") {
  std::string result(prefix);
  result += path;
  result += suffix;
  return result;
}

}             

void PathValidator::ValidateScanInputs(std::string_view csv_path,
                                       std::string_view log_path,
                                       std::string_view root_path) const {
  ValidateCsvPath(csv_path);
  ValidateLogPath(log_path);
  if (!root_path.empty()) {
    ValidateRootPath(root_path);
  }
}

void PathValidator::ValidateScanTarget(std::string_view root_path) const {
  ValidateRootPath(root_path);
}

void PathValidator::ValidateCsvPath(std::string_view csv_path) {
  namespace fs = std::filesystem;

  if (csv_path.empty()) {
    throw std::runtime_error("Путь к базе хешей не может быть пустым");
  }

  std::error_code ec;
  const auto base_status = fs::status(fs::path(csv_path), ec);

  if (ec) {
    if (ec == std::errc::no_such_file_or_directory) {
      throw std::runtime_error(
          MakePathError("Файл базы хешей не найден: ", csv_path));
    }
    if (ec == std::errc::permission_denied) {
      throw std::runtime_error(
          MakePathError("Нет прав доступа к файлу базы хешей: ", csv_path));
    }
    throw std::runtime_error(MakePathError(
        "Ошибка доступа к файлу базы хешей: ", csv_path,
        " (" + ec.message() + ")"));
  }

  if (!fs::is_regular_file(base_status)) {
    if (fs::is_directory(base_status)) {
      throw std::runtime_error(MakePathError(
          "Путь к базе хешей указывает на директорию, а не файл: ", csv_path));
    }
    throw std::runtime_error(MakePathError(
        "Путь к базе хешей не является обычным файлом: ", csv_path));
  }

  std::ifstream test_base{std::string(csv_path)};
  if (!test_base.is_open()) {
    throw std::runtime_error(MakePathError(
        "Не удается открыть файл базы хешей для чтения: ", csv_path));
  }
}

void PathValidator::ValidateLogPath(std::string_view log_path) {
  namespace fs = std::filesystem;

  if (log_path.empty()) {
    throw std::runtime_error("Путь к файлу лога не может быть пустым");
  }

  const fs::path log_file_path{std::string(log_path)};
  const fs::path log_dir = log_file_path.parent_path();

  if (log_file_path.empty() || !log_file_path.has_filename()) {
    throw std::runtime_error(
        MakePathError("Некорректный путь к файлу лога: ", log_path));
  }

  if (!log_dir.empty()) {
    std::error_code ec;
    fs::status(log_dir, ec);

    if (ec && ec != std::errc::no_such_file_or_directory) {
      throw std::runtime_error("Ошибка доступа к директории лога: " +
                               log_dir.string() + " (" + ec.message() + ")");
    }

    if (!fs::exists(log_dir, ec)) {
      if (!fs::create_directories(log_dir, ec)) {
        if (ec) {
          throw std::runtime_error(
              "Не удается создать директорию для лога: " + log_dir.string() +
              " (" + ec.message() + ")");
        }
        throw std::runtime_error(
            "Не удается создать директорию для лога: " + log_dir.string());
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
}

void PathValidator::ValidateRootPath(std::string_view root_path) {
  namespace fs = std::filesystem;

  std::error_code ec;
  const auto root_status = fs::status(fs::path(root_path), ec);

  if (ec) {
    if (ec == std::errc::no_such_file_or_directory) {
      throw std::runtime_error(MakePathError(
          "Директория для сканирования не найдена: ", root_path));
    }
    if (ec == std::errc::permission_denied) {
      throw std::runtime_error(MakePathError(
          "Нет прав доступа к директории сканирования: ", root_path));
    }
    throw std::runtime_error(MakePathError(
        "Ошибка доступа к директории сканирования: ", root_path,
        " (" + ec.message() + ")"));
  }

  if (!fs::is_directory(root_status)) {
    throw std::runtime_error(MakePathError(
        "Указанный путь не является директорией: ", root_path));
  }

  const auto test_iter = fs::directory_iterator(fs::path(root_path), ec);
  if (ec == std::errc::permission_denied) {
    throw std::runtime_error(MakePathError(
        "Нет прав на чтение директории сканирования: ", root_path));
  }
}
