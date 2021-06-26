#pragma once

#include <string>
#include <vector>

namespace musicd {

const std::string bytes_to_hex(const std::string &bytes);

std::string sha1sum(const std::string &path);

std::string tolower(const std::string &in);

std::string filetype_extension(const std::string &path);

std::unique_ptr<std::string> read_file(std::string path);

template <typename T>
bool vector_contains(const std::vector<T> &haystack, const T &needle) {
  for (auto &entry : haystack) {
    if (needle == entry) {
      return true;
    }
  }
  return false;
}

} // namespace musicd
