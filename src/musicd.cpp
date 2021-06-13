#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <thread>

#include <openssl/sha.h>

#include <pqxx/binarystring>
#include <pqxx/pqxx>

#include <taglib/fileref.h>
#include <taglib/tag.h>

#include <Magick++.h>

#include <track.pb.h>

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

static const char *INSERT_TRACK = "pq_INSERT_TRACK";
static const char *INSERT_IMAGE = "pq_INSERT_IMAGE";
static const char *SELECT_TRACK_PATH_BY_CHECKSUM =
    "pq_SELECT_TRACK_PATH_BY_CHECKSUM";
static const char *SELECT_IMAGE_PATH_BY_CHECKSUM =
    "pq_SELECT_IMAGE_PATH_BY_CHECKSUM";

enum class PacketOpcode : uint32_t {
  // Trigger update of remote database
  // No data arguments
  // Zero-len response comes after update is complete
  UPDATE_REMOTE_DB = 0,

  // Fetch serialized database information
  // No data arguments
  // Response is protobuf-serialized db info
  FETCH_DB = 1,

  // Fetch track with specified checksum
  // Data argument is checksum (20 bytes)
  // Response is raw track data (variable size)
  FETCH_TRACK = 2,

  // Fetch image with specified checksum
  // Data argument is checksum (20 bytes)
  // Response is raw image data (variable size)
  FETCH_IMAGE = 3,
};

pqxx::connection pq_conn;

std::atomic<bool> db_thread_update_request{false};
std::thread db_update_thread;

void pq_prepare(pqxx::connection &conn) {
  conn.prepare(INSERT_TRACK, "INSERT INTO track ("
                             "raw_path, "
                             "parent_path, "
                             "checksum, "
                             "tag_title, "
                             "tag_artist, "
                             "tag_album, "
                             "tag_year, "
                             "tag_comment, "
                             "tag_track, "
                             "tag_genre "
                             ") VALUES ( "
                             "$1, "
                             "$2, "
                             "$3, "
                             "$4, "
                             "$5, "
                             "$6, "
                             "$7, "
                             "$8, "
                             "$9, "
                             "$10 "
                             ") ON CONFLICT (checksum) DO UPDATE SET "
                             "raw_path = EXCLUDED.raw_path, "
                             "parent_path = EXCLUDED.parent_path, "
                             "tag_title = EXCLUDED.tag_title, "
                             "tag_artist = EXCLUDED.tag_artist, "
                             "tag_album = EXCLUDED.tag_album, "
                             "tag_year = EXCLUDED.tag_year, "
                             "tag_comment = EXCLUDED.tag_comment, "
                             "tag_track = EXCLUDED.tag_track, "
                             "tag_genre = EXCLUDED.tag_genre"

  );
  conn.prepare(INSERT_IMAGE, "INSERT INTO image ("
                             "raw_path, "
                             "parent_path, "
                             "checksum "
                             ") VALUES ( "
                             "$1, "
                             "$2, "
                             "$3 "
                             ") ON CONFLICT (checksum) DO UPDATE SET "
                             "raw_path = EXCLUDED.raw_path, "
                             "parent_path = EXCLUDED.parent_path ");

  conn.prepare(SELECT_TRACK_PATH_BY_CHECKSUM,
               "SELECT raw_path FROM track WHERE checksum = $1");

  conn.prepare(SELECT_IMAGE_PATH_BY_CHECKSUM,
               "SELECT raw_path FROM image WHERE checksum = $1");
}

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

struct TrackedFile {
  std::string path;
  std::string checksum;

  std::string parent_path(const std::string base_path) {
    const std::filesystem::path parent_path =
        std::filesystem::path(path).parent_path();
    return parent_path.lexically_relative(base_path);
  }
};

struct MusicFile : TrackedFile {
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

struct ImageFile : TrackedFile {};

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

void ingest_music_file(pqxx::work &pq_transaction, const std::string &base_path,
                       const std::string &path) {
  // Try and load our required metadata
  auto music_file = parse_music_file(path);
  if (!music_file) {
    return;
  }

  music_file->print();

  // Save to the db
  pq_transaction
      .prepared(INSERT_TRACK)(music_file->path)(
          music_file->parent_path(base_path))(
          pqxx::binarystring(music_file->checksum))(music_file->tags.title)(
          music_file->tags.artist)(music_file->tags.album)(
          music_file->tags.year)(music_file->tags.comment)(
          music_file->tags.track)(music_file->tags.genre)
      .exec();
}

void ingest_image_file(pqxx::work &pq_transaction, const std::string &base_path,
                       const std::string &path) {
  // Try and load our required metadata
  auto image_file = parse_image_file(path);
  if (!image_file) {
    return;
  }

  // Save to the db
  pq_transaction
      .prepared(INSERT_IMAGE)(image_file->path)(image_file->parent_path(
          base_path))(pqxx::binarystring(image_file->checksum))
      .exec();
}

void ingest_file(pqxx::work &pq_transaction,
                 const std::filesystem::path &base_path,
                 const std::filesystem::directory_entry &file) {
  // We need to determine what type of file this is - for now, rely on file
  // extension
  const std::string extension = filetype_extension(file.path());
  if (vector_contains(MUSIC_FILETYPES, extension)) {
    ingest_music_file(pq_transaction, base_path, file.path());
  } else if (vector_contains(IMAGE_FILETYPES, extension)) {
    ingest_image_file(pq_transaction, base_path, file.path());
  } else if (vector_contains(PLAYLIST_FILETYPES, extension)) {
    // Ignore
  } else if (vector_contains(IGNORE_FILETYPES, extension)) {
    // Ignore
  } else {
    LOG_I("Unknown file extension '%s' for path '%s'\n", extension.c_str(),
          file.path().c_str());
  }
}

void walk_music_dir(pqxx::connection &pq_conn, const char *path) {
  // Create a new transaction
  pqxx::work pq_transaction(pq_conn);

  // Delete all the old data in the db
  auto trunc_track_result = pq_transaction.exec("DELETE FROM track");
  auto trunc_image_result = pq_transaction.exec("DELETE FROM image");
  LOG_I("Truncated %lu old tracks / %lu old images\n",
        trunc_track_result.affected_rows(), trunc_image_result.affected_rows());

  // Canonicalize base path
  std::filesystem::path base_path(path);

  // Iterate all files / directories in the search path
  for (const auto &dirent :
       std::filesystem::recursive_directory_iterator(path)) {
    // If we encounter a regular file, attempt to handle
    if (dirent.is_regular_file()) {
      ingest_file(pq_transaction, base_path, dirent);
    }
  }

  // Commit our DB update
  pq_transaction.commit();
}

void pgusage() {
  fprintf(stderr,
          "PSQL variables not set! Please ensure the following are defined:\n"
          "PGHOST (db host)\n"
          "PGDATABASE (database)\n"
          "PGUSER (username)\n"
          "PGPASSWORD (password)\n");
  exit(1);
}

int set_socket_nonblocking(int fd) {
  int32_t socketfd_flags = fcntl(fd, F_GETFL);
  if (socketfd_flags == -1) {
    LOG_E("fcntl: get flags: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  int err = fcntl(fd, F_SETFL, socketfd_flags | O_NONBLOCK);
  if (err == -1) {
    LOG_E("fcntl: set flags: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int set_socket_keepalive(int fd, int interval, int tolerance) {
  int ok = 0;
  ok = setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (void *)&interval,
                  sizeof(interval));
  ok = setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (void *)&interval,
                  sizeof(interval));
  ok = setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (void *)&tolerance,
                  sizeof(tolerance));
  return ok;
}

std::unique_ptr<msgs::MusicDatabase>
serialize_music_db(pqxx::connection &pq_conn) {
  auto ret = std::make_unique<msgs::MusicDatabase>();

  // Serialize all the music info
  pqxx::work txn(pq_conn);
  const char *track_select = "SELECT "
                             "raw_path, "
                             "parent_path, "
                             "checksum, "
                             "tag_title, "
                             "tag_artist, "
                             "tag_album, "
                             "tag_year, "
                             "tag_comment, "
                             "tag_track, "
                             "tag_genre "
                             "FROM track";
  for (auto const &row : txn.exec(track_select)) {
    auto *track = ret->add_tracks();
    track->set_raw_path(row[0].as<std::string>());
    track->set_parent_path(row[1].as<std::string>());
    track->set_checksum(pqxx::binarystring(row[2]).str());
    track->set_tag_title(row[3].as<std::string>());
    track->set_tag_artist(row[4].as<std::string>());
    track->set_tag_album(row[5].as<std::string>());
    track->set_tag_year(row[6].as<unsigned>());
    track->set_tag_comment(row[7].as<std::string>());
    track->set_tag_track(row[8].as<unsigned>());
    track->set_tag_genre(row[9].as<std::string>());
  }

  // And all the image info
  const char *image_select = "SELECT * from image";
  for (auto const &row : txn.exec(image_select)) {
    auto *image = ret->add_images();
    image->set_raw_path(row[0].as<std::string>());
    image->set_parent_path(row[1].as<std::string>());
    image->set_checksum(pqxx::binarystring(row[2]).str());
  }

  return ret;
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

std::unique_ptr<std::string> fetch_object_by_checksum(pqxx::connection &pq_conn,
                                                      const char *query,
                                                      std::string checksum) {
  // Look up the path for this checksum
  pqxx::work txn(pq_conn);
  pqxx::result rows = txn.exec_prepared(query, pqxx::binarystring(checksum));

  // If it doesn't exist, return null
  if (rows.size() == 0) {
    return nullptr;
  }

  // Extract the path
  const std::string path = rows[0][0].as<std::string>();
  LOG_I("Content ID %s: Path %s\n", bytes_to_hex(checksum).c_str(),
        path.c_str());

  // Read the file and return
  return read_file(path);
}

std::unique_ptr<std::string> fetch_track_by_checksum(pqxx::connection &pq_conn,
                                                     std::string checksum) {
  return fetch_object_by_checksum(pq_conn, SELECT_TRACK_PATH_BY_CHECKSUM,
                                  checksum);
}

std::unique_ptr<std::string> fetch_image_by_checksum(pqxx::connection &pq_conn,
                                                     std::string checksum) {
  return fetch_object_by_checksum(pq_conn, SELECT_IMAGE_PATH_BY_CHECKSUM,
                                  checksum);
}

template <typename T> void remove_in_vector(std::vector<T> &v, int idx) {
  v[idx].swap(v.back());
  v.pop_back();
}

template <>
void remove_in_vector<struct pollfd>(std::vector<struct pollfd> &v, int idx) {
  v[idx] = v.back();
  v.pop_back();
}

int handle_packet_update_db(int fd, uint32_t nonce) {
  LOG_I("Update db for fd %d\n", fd);
  db_thread_update_request.store(true);
  return 0;
}

int send_packet_response(int fd, uint32_t nonce, PacketOpcode opcode,
                         std::string &data) {
  // TODO: proper nonblocking
  // TODO: iovec

  // Prepend nonce and data size to paylaod
  const std::string::size_type payload_size = data.size();
  uint32_t header[3];
  header[0] = nonce;
  header[1] = static_cast<uint32_t>(opcode);
  header[2] = payload_size;
  data.insert(0, reinterpret_cast<char *>(header), sizeof(header));

  unsigned total_sent = 0;
  do {
    ssize_t sent = ::send(fd, data.data() + total_sent,
                          data.size() - total_sent, /* flags */ 0);
    if (sent >= 0) {
      total_sent += sent;
    } else {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // TODO: hack
        usleep(1000);
      } else {
        LOG_E("Failed to send data on fd %d: %d: %s\n", fd, errno,
              strerror(errno));
        return EXIT_FAILURE;
      }
    }
  } while (total_sent < data.size());

  return total_sent;
}

int handle_packet_fetch_db(int fd, uint32_t nonce) {
  LOG_I("Fetch db for fd %d\n", fd);
  // Serialize database to pb
  std::unique_ptr<msgs::MusicDatabase> db = serialize_music_db(pq_conn);

  // Send our response
  std::string pb_data;
  db->SerializeToString(&pb_data);

  LOG_I("Serialized DB size: %lu\n", pb_data.size());
  return send_packet_response(fd, nonce, PacketOpcode::FETCH_DB, pb_data);
}

int handle_packet_fetch_track(int fd, uint32_t nonce, std::string req) {
  LOG_I("Fetch track %s for fd %d\n", bytes_to_hex(req).c_str(), fd);

  // Try and fetch a track with this checksum
  std::unique_ptr<std::string> track_data =
      fetch_track_by_checksum(pq_conn, req);

  // If not found, send zero-len response
  if (track_data == nullptr) {
    std::string empty_resp = "";
    LOG_E("Failed to find track for checksum %s\n", bytes_to_hex(req).c_str());
    return send_packet_response(fd, nonce, PacketOpcode::FETCH_TRACK,
                                empty_resp);
  }

  // Otherwise, send full data back
  LOG_I("Sending response for track %s size %lu\n", bytes_to_hex(req).c_str(),
        track_data->size());
  return send_packet_response(fd, nonce, PacketOpcode::FETCH_TRACK,
                              *track_data);
}

int handle_packet_fetch_image(int fd, uint32_t nonce, std::string req) {
  LOG_I("Fetch image %s for fd %d\n", bytes_to_hex(req).c_str(), fd);

  // Try and fetch a image with this checksum
  std::unique_ptr<std::string> image_data =
      fetch_image_by_checksum(pq_conn, req);

  // If not found, send zero-len response
  if (image_data == nullptr) {
    std::string empty_resp = "";
    LOG_E("Failed to find image for checksum %s\n", bytes_to_hex(req).c_str());
    return send_packet_response(fd, nonce, PacketOpcode::FETCH_IMAGE,
                                empty_resp);
  }

  // Otherwise, we have valid image data - ensure it's shrunk down if doing so
  // will actually make it smaller
  const std::string::size_type initial_image_size = image_data->size();
  try {
    Magick::Blob blob(image_data->data(), image_data->size());
    Magick::Image raw_image(blob);
    raw_image.resize("512x512");
    raw_image.magick("JPEG");
    raw_image.write(&blob);
    const std::string::size_type final_image_size = blob.length();
    if (final_image_size < initial_image_size) {
      image_data->assign((const char *)blob.data(), blob.length());
    }
  } catch (Magick::WarningCorruptImage &e) {
    LOG_E("Failed to resize image: %s\n", e.what());
  }

  // Otherwise, send full data back
  LOG_I("Sending response for image %s, size %lu\n", bytes_to_hex(req).c_str(),
        image_data->size());
  return send_packet_response(fd, nonce, PacketOpcode::FETCH_IMAGE,
                              *image_data);
}

int handle_packet(int fd, uint32_t nonce, PacketOpcode cmd, std::string &data) {
  switch (cmd) {
  case PacketOpcode::UPDATE_REMOTE_DB: {
    return handle_packet_update_db(fd, nonce);
    break;
  }
  case PacketOpcode::FETCH_DB: {
    return handle_packet_fetch_db(fd, nonce);
    break;
  }
  case PacketOpcode::FETCH_TRACK: {
    return handle_packet_fetch_track(fd, nonce, data);
    break;
  }
  case PacketOpcode::FETCH_IMAGE: {
    return handle_packet_fetch_image(fd, nonce, data);
    break;
  }
  default: {
    LOG_E("Unknown opcode %08x\n", static_cast<uint32_t>(cmd));
    return -1;
  }
  }

  return 0;
}

int process_incoming_data(int fd, std::string &slab) {
  // Is there enough data to peek a packet header
  static const unsigned HEADER_SIZE = sizeof(uint32_t) * 3;
  if (slab.size() < HEADER_SIZE) {
    // LOG_I("Slab size %lu < header size (%u)\n", slab.size(), HEADER_SIZE);
    return 0;
  }

  // Pull off the packet header
  uint32_t *data_32 = reinterpret_cast<uint32_t *>(slab.data());
  const uint32_t nonce = data_32[0];
  const uint32_t cmd = data_32[1];
  const uint32_t data_len = data_32[2];

  // If the data is not yet all here, return
  if (slab.size() < data_len + HEADER_SIZE) {
    LOG_I("Slab size %lu < header size (%u) + data len (%u)\n", slab.size(),
          HEADER_SIZE, data_len);
    return 0;
  }

  // If there _is_ enough data to pull off the entire packet, do so
  std::string data = std::string(slab.data() + HEADER_SIZE, data_len);

  // Remove this data from the front of the slab
  slab.erase(0, HEADER_SIZE + data_len);

  // Go handle whatever this packet is
  return handle_packet(fd, nonce, PacketOpcode(cmd), data);
}

int main(int argc, char *argv[]) {
  // Init postgres
  if (!getenv("PGHOST") || !getenv("PGDATABASE") || !getenv("PGUSER") ||
      !getenv("PGPASSWORD")) {
    pgusage();
  }
  pqxx::thread_safety_model pqxx_model = pqxx::describe_thread_safety();
  LOG_I("Pqxx thread-safe? %s - %s", pqxx_model.safe_libpq ? "yes" : "no",
        pqxx_model.description.c_str());

  pq_prepare(pq_conn);

  // Check args
  if (argc != 2) {
    fprintf(stderr, "Usage: %s [Music Dir]\n", argv[0]);
  }
  const char *music_basedir = argv[1];

  // Init imagemagick
  Magick::InitializeMagick(*argv);

  // Spawn filesystem crawler thread
  db_update_thread = std::thread([&]() {
    while (true) {
      if (db_thread_update_request.exchange(false)) {
        walk_music_dir(pq_conn, music_basedir);
      }
      usleep(1'000'000);
    }
  });

  const char *bind_addr = "0.0.0.0";
  const char *bind_port = "5959";

  // Try and resolve the bind address / port
  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  struct addrinfo *servinfo;
  int err = getaddrinfo(bind_addr, bind_port, &hints, &servinfo);
  if (err != 0) {
    LOG_E("getaddrinfo: %s\n", gai_strerror(err));
    return EXIT_FAILURE;
  }

  // Loop through the results and bind to the first thing we can
  struct addrinfo *p = nullptr;
  int sockfd;
  for (p = servinfo; p != nullptr; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      LOG_I("socket: %s\n", strerror(errno));
      continue;
    }

    const int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      LOG_E("setsockopt: %s\n", strerror(errno));
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      LOG_E("bind: %s\n", strerror(errno));
      close(sockfd);
      continue;
    }

    break;
  }
  freeaddrinfo(servinfo);

  // If we iterated all the way to the end of the addrinfo list without
  // managing to bind something, then we did not successfully create a listen
  // socket.
  if (!p) {
    LOG_E("failed to bind to %s: %s\n", bind_addr, bind_port);
    return EXIT_FAILURE;
  }

  // Enable listen
  if (listen(sockfd, /* backlog */ 64) == -1) {
    LOG_E("listen: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  // Nonblocking
  if (set_socket_nonblocking(sockfd)) {
    return EXIT_FAILURE;
  }

  // Socket is up
  LOG_I("%s: %s: listening\n", bind_addr, bind_port);

  std::vector<struct pollfd> pollfds;
  std::vector<std::string> slabs;

  // Add listen socket to poll set

  auto add_pollfd = [&](int fd) {
    pollfds.emplace_back();
    pollfds.back().fd = fd;
    pollfds.back().events = POLLIN;
    slabs.emplace_back();
  };
  auto remove_pollfd = [&](int index) {
    remove_in_vector(pollfds, index);
    remove_in_vector(slabs, index);
  };

  add_pollfd(sockfd);

  while (true) {
    int event_count = poll(pollfds.data(), pollfds.size(), /* timeout */ 1000);
    if (event_count < 0) {
      LOG_E("Poll error: %d: %s\n", errno, strerror(errno));
      continue;
    }

    for (unsigned i = 0; i < pollfds.size(); i++) {
      if (i == 0) {
        // Listen socket
        // Handle the listening socket.
        if (pollfds[i].revents & POLLERR) {
          LOG_E("Poll error for listen fd: %d: %s\n", errno, strerror(errno));
          return EXIT_FAILURE;
        }

        struct sockaddr_storage their_addr = {};
        socklen_t ss_size = sizeof(their_addr);
        int conn_fd =
            accept(pollfds[i].fd, (struct sockaddr *)&their_addr, &ss_size);
        if (conn_fd == -1) {
          switch (errno) {
          case EINTR:
            // If the call was interrupted, we just try again.
            continue;
            break;
          case EAGAIN:
            // If we would block, that's normal. Just keep trying.
            continue;
            break;
          case ENETDOWN:
          case EPROTO:
          case ENOPROTOOPT:
          case EHOSTDOWN:
          case ENONET:
          case EHOSTUNREACH:
          case EOPNOTSUPP:
          case ENETUNREACH:
            LOG_E("accept: %d: %s\n", errno, strerror(errno));
            continue;
            break;
          case EPERM:
            LOG_E("accept: %d: %s\n", errno, strerror(errno));
            continue;
            break;
          case EMFILE:
          case ENFILE:
          case ENOBUFS:
          case ENOMEM:
          default:
            // A hard error. This kills the server.
            LOG_E("accept: %d: %s\n", errno, strerror(errno));
            return EXIT_FAILURE;
            break;
          }
        }

        // Get address of incoming connection
        char inet_addr_str[INET6_ADDRSTRLEN];
        auto get_in_addr = [](struct sockaddr *s) -> void * {
          if (s->sa_family == AF_INET) {
            return &(((struct sockaddr_in *)s)->sin_addr);
          }
          return &(((struct sockaddr_in6 *)s)->sin6_addr);
        };
        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr), inet_addr_str,
                  sizeof(inet_addr_str));
        LOG_I("Connection from %s on new fd %d\n", inet_addr_str, conn_fd);

        // Setup the socket as desired.
        set_socket_nonblocking(conn_fd);
        set_socket_keepalive(conn_fd, /* interval secodns */ 10,
                             /* tolerance */ 2);

        add_pollfd(conn_fd);
      } else {
        // Client socket
        // Problems with the socket?
        if (pollfds[i].revents & (POLLERR | POLLHUP)) {
          // Socket problem, disconnect them
          LOG_I("Poll error for fd %d\n", pollfds[i].fd);
          close(pollfds[i].fd);
          remove_pollfd(i);
          continue;
        }

        // Try and consume socket data
        char buf[1024];
        int read_size;
        do {
          read_size = read(pollfds[i].fd, buf, sizeof(buf));
          if (read_size > 0) {
            LOG_I("Rx'd %u bytes on fd %d\n", read_size, pollfds[i].fd);
            slabs[i].append(buf, read_size);
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              // Fine
              break;
            } else {
              LOG_E("read fd %d: %d: %s\n", pollfds[i].fd, errno,
                    strerror(errno));
              close(pollfds[i].fd);
              remove_pollfd(i);

              goto CONTINUE;
            }
          }
        } while (read_size);

        // If we didn't hit an error, we must have read data, so go process the
        // current slab
        int process_ok;
        while ((process_ok = process_incoming_data(pollfds[i].fd, slabs[i])) >
               0) {
        }
        if (process_ok < 0) {
          LOG_E("Error processing packets on fd %d, closing\n", pollfds[i].fd);
          close(pollfds[i].fd);
          remove_pollfd(i);
        }
      CONTINUE:
        continue;
      }
    }
  }

  return EXIT_SUCCESS;
}
