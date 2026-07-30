#include "core/directory_walker.hpp"

#include <system_error>

void DirectoryWalker::Enumerate(const std::filesystem::path& root,
                                const FileVisitor& on_file,
                                const ErrorHandler& on_error) {
  namespace fs = std::filesystem;

  try {
    std::error_code ec;
    fs::recursive_directory_iterator iter(
        root, fs::directory_options::skip_permission_denied, ec);

    if (ec) {
      on_error(root, "ОШИБКА открытия директории для обхода: " + ec.message());
      return;
    }

    while (iter != fs::recursive_directory_iterator()) {
      try {
        const auto& entry = *iter;

        if (entry.is_directory(ec)) {
          if (ec) {
            on_error(entry.path(),
                     "ОШИБКА проверки директории: " + ec.message() +
                         ", пропускаем вложенные файлы");
            iter.disable_recursion_pending();
            ec.clear();
          } else {
            // Проверяем, можно ли читать содержимое директории, прежде чем
            // разрешать рекурсивный обход.
            std::error_code access_ec;
            const auto test_iter =
                fs::directory_iterator(entry.path(), access_ec);

            if (access_ec) {
              on_error(entry.path(),
                       "Нет прав доступа к директории (" +
                           access_ec.message() +
                           "), пропускаем рекурсивный обход");
              iter.disable_recursion_pending();
            }
          }
        } else if (entry.is_regular_file(ec) && !ec) {
          on_file(entry.path());
        } else if (ec) {
          on_error(entry.path(), "ОШИБКА проверки элемента: " + ec.message());
          ec.clear();
        }
      } catch (const fs::filesystem_error& e) {
        on_error(root, std::string("ОШИБКА файловой системы: ") + e.what() +
                           ", продолжаем обход");
        iter.disable_recursion_pending();
      }

      std::error_code increment_ec;
      iter.increment(increment_ec);
      if (increment_ec) {
        on_error(root, "ОШИБКА перехода к следующему элементу: " +
                           increment_ec.message());
        break;
      }
    }
  } catch (const std::filesystem::filesystem_error& e) {
    on_error(root,
             std::string("Критическая ошибка при обходе: ") + e.what());
  }
}
