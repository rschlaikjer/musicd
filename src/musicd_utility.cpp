#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <openssl/sha.h>

#include <musicd/log.hpp>
#include <musicd/utility.hpp>

namespace musicd {

const std::string bytes_to_hex(const std::string &bytes) {
  std::string ret;
  ret.resize(bytes.size() * 2);
  auto nibble_to_hex = [](uint8_t nibble) -> char {
    nibble &= 0xF;
    if (nibble < 10)
      return '0' + nibble;
    return 'A' + (nibble - 10);
  };

  for (std::string::size_type i = 0; i < bytes.size(); i++) {
    uint8_t byte = bytes[i];
    ret[i * 2] = nibble_to_hex(byte >> 4);
    ret[i * 2 + 1] = nibble_to_hex(byte);
  }

  return ret;
}

std::string sha1sum(const std::string &path) {
  // Open file
  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    return "";
  }

  // Defer file close
  std::shared_ptr<void> _defer_close_fd(nullptr, [=](...) { ::close(fd); });

  // Get the file size
  const off_t file_size = ::lseek(fd, 0, SEEK_END);
  if (file_size < 0) {
    return "";
  }

  // Move back to the start of the file
  if (lseek(fd, 0, SEEK_SET) < 0) {
    return "";
  }

  // Map data
  uint8_t *const mmapped_data = static_cast<uint8_t *>(
      mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
  if (mmapped_data == nullptr) {
    return "";
  }

  // Defer munmap
  std::shared_ptr<void> _defer_munmap(
      nullptr, [=](...) { ::munmap(mmapped_data, file_size); });

  // Digest
  std::string digest;
  digest.resize(SHA_DIGEST_LENGTH);
  SHA1(mmapped_data, file_size, reinterpret_cast<uint8_t *>(digest.data()));
  return digest;
}

std::string tolower(const std::string &in) {
  std::string out;
  out.resize(in.size());
  for (std::string::size_type i = 0; i < in.size(); i++) {
    out[i] = std::tolower(in[i]);
  }
  return out;
}

std::string filetype_extension(const std::string &path) {
  // Find the last instance of '.'
  const auto pos = path.rfind(".");
  if (pos == std::string::npos) {
    return "";
  }
  return tolower(path.substr(pos));
}

std::unique_ptr<std::string> read_file(std::string path) {
  // Try and open the file
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    LOG_E("Failed to open %s: %d: %s\n", path.c_str(), errno, strerror(errno));
    return nullptr;
  }
  std::shared_ptr<void> _defer_close_fd(nullptr, [=](...) { ::close(fd); });

  // Get total file size
  const ssize_t file_size = ::lseek(fd, 0, SEEK_END);
  if (file_size < 0) {
    LOG_E("Failed to seek %s: %d: %s\n", path.c_str(), errno, strerror(errno));
    return nullptr;
  }

  // Move back to start of file
  if (lseek(fd, 0, SEEK_SET) < 0) {
    LOG_E("Failed to seek %s: %d: %s\n", path.c_str(), errno, strerror(errno));
    return nullptr;
  }

  // Reserve a string to hold the file data
  std::unique_ptr<std::string> ret = std::make_unique<std::string>();
  ret->resize(file_size);

  // Read the entire file
  static const ssize_t read_size = 16 * 1024;
  ssize_t total_read = 0;
  while (total_read < file_size) {
    ssize_t read_ok = ::read(fd, ret->data() + total_read,
                             std::min(read_size, file_size - total_read));
    if (read_ok < 0) {
      LOG_E("Failed to read %s: %d: %s\n", path.c_str(), errno,
            strerror(errno));
      return nullptr;
    }
    total_read += read_ok;
  }

  return ret;
}

} // namespace musicd
