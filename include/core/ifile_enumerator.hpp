#pragma once

#include <filesystem>
#include <functional>
#include <string>

class IFileEnumerator {
 public:
  using FileVisitor = std::function<void(const std::filesystem::path&)>;
  using ErrorHandler =
      std::function<void(const std::filesystem::path&, const std::string&)>;

  virtual ~IFileEnumerator() = default;

  virtual void Enumerate(const std::filesystem::path& root,
                         const FileVisitor& on_file,
                         const ErrorHandler& on_error) = 0;
};
