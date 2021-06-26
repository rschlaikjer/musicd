#pragma once

#include <filesystem>
#include <string>

#include <pqxx/binarystring>
#include <pqxx/pqxx>

#include <track.pb.h>

#include <musicd/utility.hpp>

namespace musicd {

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

// Prepare named transactions for connection
void pq_prepare(pqxx::connection &conn);

// Update the database by walking the specified music path
void update_db(pqxx::connection &pq_conn, const char *path);

// Fetch a protocol buffer encoded copy of the database
std::unique_ptr<msgs::MusicDatabase>
serialize_music_db(pqxx::connection &pq_conn);

// Fetch content blobs by checksum
std::unique_ptr<std::string> fetch_object_by_checksum(pqxx::connection &pq_conn,
                                                      const char *query,
                                                      std::string checksum);
std::unique_ptr<std::string> fetch_track_by_checksum(pqxx::connection &pq_conn,
                                                     std::string checksum);
std::unique_ptr<std::string> fetch_image_by_checksum(pqxx::connection &pq_conn,
                                                     std::string checksum);

std::unique_ptr<MusicFile> parse_music_file(const std::string &path);
std::unique_ptr<ImageFile> parse_image_file(const std::string &path);
void ingest_music_file(pqxx::work &pq_transaction, const std::string &base_path,
                       const std::string &path);
void ingest_image_file(pqxx::work &pq_transaction, const std::string &base_path,
                       const std::string &path);
void ingest_file(pqxx::work &pq_transaction,
                 const std::filesystem::path &base_path,
                 const std::filesystem::directory_entry &file);

} // namespace musicd
