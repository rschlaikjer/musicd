#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <iomanip>
#include <iostream>

#include <openssl/sha.h>

#include <fileref.h>
#include <tag.h>
#include <tpropertymap.h>

#define LOG_I(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

static const std::vector<std::string> MUSIC_FILETYPES = {
    ".mp3", ".flac", ".ogg", ".m4a", ".mpc",
};

static const std::vector<std::string> IMAGE_FILETYPES = {
    ".jpg", ".jpeg", ".gif", ".png", ".bmp",
};

static const std::vector<std::string> PLAYLIST_FILETYPES = {
    ".m3u",
    ".m3u8",
};

static const std::vector<std::string> IGNORE_FILETYPES = {
    ".log", ".cue", ".nfo", ".txt", ".pdf", ".sfv", ".swf",
};

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

struct MusicFile {
  std::string path;
  std::string checksum;

  // Tag fields
  struct {
    std::string title;
    std::string artist;
    std::string album;
    unsigned year;
    std::string comment;
    unsigned track;
    std::string genre;
  } tags;

  void print() {
    fprintf(stderr,
            "Track: %s\n"
            "    Checksum:  %s\n"
            "    Title:     %s\n"
            "    Artist:    %s\n"
            "    Album:     %s\n"
            "    Year:      %u\n"
            "    Comment:   %s\n"
            "    Track:     %u\n"
            "    Genre:     %s\n",
            path.c_str(), bytes_to_hex(checksum).c_str(), tags.title.c_str(),
            tags.artist.c_str(), tags.album.c_str(), tags.year,
            tags.comment.c_str(), tags.track, tags.genre.c_str());
  }
};

struct ImageFile {
  std::string path;
  std::string checksum;
};

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

bool vector_contains(const std::vector<std::string> &haystack,
                     const std::string &needle) {
  for (auto &entry : haystack) {
    if (needle == entry) {
      return true;
    }
  }
  return false;
}

std::unique_ptr<MusicFile> parse_music_file(const std::string &path) {
  auto ret = std::make_unique<MusicFile>();
  ret->path = path;
  ret->checksum = sha1sum(path);
  if (ret->checksum.empty()) {
    LOG_E("Failed to calculate checksum for '%s'\n", path.c_str());
    return nullptr;
  }

  // Try and load tag info
  TagLib::FileRef file_ref(path.c_str());
  if (file_ref.isNull() || !file_ref.tag()) {
    LOG_E("Failed to read tag information for '%s'\n", path.c_str());
    return nullptr;
  }

  // Extract important tag properties, using unicode for strings
  TagLib::Tag *tag = file_ref.tag();
  ret->tags.title = tag->title().to8Bit(true);
  ret->tags.artist = tag->artist().to8Bit(true);
  ret->tags.album = tag->album().to8Bit(true);
  ret->tags.year = tag->year();
  ret->tags.comment = tag->comment().to8Bit(true);
  ret->tags.track = tag->track();
  ret->tags.genre = tag->genre().to8Bit(true);

  return ret;
}

std::unique_ptr<ImageFile> parse_image_file(const std::string &path) {
  auto ret = std::make_unique<ImageFile>();
  ret->path = path;
  ret->checksum = sha1sum(path);
  if (ret->checksum.empty()) {
    LOG_E("Failed to calculate checksum for %s\n", path.c_str());
    return nullptr;
  }

  return ret;
}

void ingest_music_file(const std::string &path) {
  // Try and load our required metadata
  auto music_file = parse_music_file(path);
  if (!music_file) {
    return;
  }

  music_file->print();

  // Save to the db
  // TODO
}

void ingest_image_file(const std::string &path) {
  // Try and load our required metadata
  auto image_file = parse_image_file(path);
  if (!image_file) {
    return;
  }

  // Save to the db
  // TODO
}

void ingest_file(const std::filesystem::directory_entry &file) {
  // We need to determine what type of file this is - for now, rely on file
  // extension
  const std::string extension = filetype_extension(file.path());
  if (vector_contains(MUSIC_FILETYPES, extension)) {
    ingest_music_file(file.path());
  } else if (vector_contains(IMAGE_FILETYPES, extension)) {
    ingest_image_file(file.path());
  } else if (vector_contains(PLAYLIST_FILETYPES, extension)) {
    // Ignore
  } else if (vector_contains(IGNORE_FILETYPES, extension)) {
    // Ignore
  } else {
    LOG_I("Unknown file extension '%s' for path '%s'\n", extension.c_str(),
          file.path().c_str());
  }
}

void walk_music_dir(const char *path) {
  // Iterate all files / directories in the search path
  for (const auto &dirent :
       std::filesystem::recursive_directory_iterator(path)) {
    // If we encounter a regular file, attempt to handle
    if (dirent.is_regular_file()) {
      ingest_file(dirent);
    }
  }
}

int main(int argc, char *argv[]) {
  walk_music_dir(argv[1]);
  return 0;
}
