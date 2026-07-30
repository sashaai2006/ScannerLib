#pragma once

#include "core/ifile_enumerator.hpp"

class DirectoryWalker : public IFileEnumerator {
 public:
  void Enumerate(const std::filesystem::path& root,
                 const FileVisitor& on_file,
                 const ErrorHandler& on_error) override;
};
