
#include <pqxx/binarystring>
#include <pqxx/pqxx>

#include <taglib/fileref.h>
#include <taglib/tag.h>

#include <musicd/db.hpp>
#include <musicd/log.hpp>

namespace musicd {

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
static const char *DELETE_TRACK_BY_CHECKSUM = "DELETE_TRACK_BY_CHECKSUM";
static const char *DELETE_IMAGE_BY_CHECKSUM = "DELETE_IMAGE_BY_CHECKSUM";

void pq_prepare(pqxx::connection &conn) {
  conn.prepare(INSERT_TRACK, "INSERT INTO track ("
                             "raw_path, "
                             "parent_path, "
                             "checksum, "
                             "file_mtime, "
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
                             "$10, "
                             "$11 "
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
                             "checksum, "
                             "file_mtime "
                             ") VALUES ( "
                             "$1, "
                             "$2, "
                             "$3, "
                             "$4 "
                             ") ON CONFLICT (checksum) DO UPDATE SET "
                             "raw_path = EXCLUDED.raw_path, "
                             "parent_path = EXCLUDED.parent_path ");

  conn.prepare(SELECT_TRACK_PATH_BY_CHECKSUM,
               "SELECT raw_path FROM track WHERE checksum = $1");

  conn.prepare(SELECT_IMAGE_PATH_BY_CHECKSUM,
               "SELECT raw_path FROM image WHERE checksum = $1");

  conn.prepare(DELETE_TRACK_BY_CHECKSUM,
               "DELETE FROM track WHERE checksum = $1");

  conn.prepare(DELETE_IMAGE_BY_CHECKSUM,
               "DELETE FROM image WHERE checksum = $1");
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
  // Stat the file to get its mtime
  int64_t fs_mtime =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::filesystem::last_write_time(path).time_since_epoch())
          .count();

  // If the file modification time is older than the DB record, do not bother
  {
    // Query to see if this file is already ingested
    const auto existing_track_result = pq_transaction.exec_params(
        "SELECT checksum, file_mtime FROM track WHERE raw_path = $1", path);

    // Do we already have an entry?
    if (existing_track_result.size() > 0) {
      // Extract the mtime from the DB row
      const auto &row = existing_track_result[0];
      const std::string checksum = pqxx::binarystring(row[0]).str();
      const int64_t db_mtime = row[1].as<int64_t>();

      // If the DB time is more recent, skip
      if (db_mtime > fs_mtime) {
        return;
      }
    }
  }

  // Try and load our required metadata
  auto music_file = parse_music_file(path);
  if (!music_file) {
    return;
  }

  music_file->print();

  // Save to the db
  pq_transaction
      .prepared(INSERT_TRACK)(music_file->path)(music_file->parent_path(
          base_path))(pqxx::binarystring(music_file->checksum))(fs_mtime)(
          music_file->tags.title)(music_file->tags.artist)(
          music_file->tags.album)(music_file->tags.year)(
          music_file->tags.comment)(music_file->tags.track)(
          music_file->tags.genre)
      .exec();
}

void ingest_image_file(pqxx::work &pq_transaction, const std::string &base_path,
                       const std::string &path) {
  // Stat the file to get its mtime
  int64_t fs_mtime =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::filesystem::last_write_time(path).time_since_epoch())
          .count();

  // If the file modification time is older than the DB record, do not bother
  {
    // Query to see if this file is already ingested
    const auto existing_image_result = pq_transaction.exec_params(
        "SELECT checksum, file_mtime FROM image WHERE raw_path = $1", path);

    // Do we already have an entry?
    if (existing_image_result.size() > 0) {
      // Extract the mtime from the DB row
      const auto &row = existing_image_result[0];
      const std::string checksum = pqxx::binarystring(row[0]).str();
      const int64_t db_mtime = row[1].as<int64_t>();

      // If the DB time is more recent, skip
      if (db_mtime > fs_mtime) {
        return;
      }
    }
  }

  // Try and load our required metadata
  auto image_file = parse_image_file(path);
  if (!image_file) {
    return;
  }

  // Save to the db
  pq_transaction
      .prepared(INSERT_IMAGE)(image_file->path)(image_file->parent_path(
          base_path))(pqxx::binarystring(image_file->checksum))(fs_mtime)
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

void update_db(pqxx::connection &pq_conn, const char *path) {
  // Create a new transaction
  pqxx::work pq_transaction(pq_conn);

  // First, iterate the DB and delete any entries that no longer map to existing
  // files
  {
    // Tracks
    for (const auto &track_row :
         pq_transaction.exec("SELECT raw_path, checksum FROM track")) {
      const std::string path = track_row[0].as<std::string>();
      const std::string checksum = pqxx::binarystring(track_row[2]).str();

      // Does this file still exist?
      if (std::filesystem::exists(path)) {
        // It does, keep the db entry around
        continue;
      }

      // If the file is gone, delete this DB entry
      pq_transaction.prepared(DELETE_TRACK_BY_CHECKSUM)(checksum).exec();
    }

    // Images
    for (const auto &image_row :
         pq_transaction.exec("SELECT raw_path, checksum FROM image")) {
      const std::string path = image_row[0].as<std::string>();
      const std::string checksum = pqxx::binarystring(image_row[2]).str();

      // Does this file still exist?
      if (std::filesystem::exists(path)) {
        // It does, keep the db entry around
        continue;
      }

      // If the file is gone, delete this DB entry
      pq_transaction.prepared(DELETE_IMAGE_BY_CHECKSUM)(checksum).exec();
    }
  }

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

} // namespace musicd
