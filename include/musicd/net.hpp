#pragma once

#include <poll.h>
#include <stdint.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <pqxx/pqxx>

#include <musicd/threadpool.hpp>

namespace musicd {

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

struct NetServer {

  struct Settings {
    std::string bind_addr;
    std::string bind_port;

    std::string music_dir;
    std::string cache_dir;
  };

  struct TranscodeJob {
    int fd = -1;
    uint32_t nonce = -1;
    std::string hash;
    std::string input_path;

    // Response
    bool success = false;
  };

  NetServer(Settings settings);
  ~NetServer();

  bool init();
  int loop();

protected:
  int process_incoming_data(int fd, std::string &slab);
  int send_packet_response(int fd, uint32_t nonce, PacketOpcode opcode,
                           std::string &data);
  int handle_packet_update_db(int fd, uint32_t nonce);
  int handle_packet_fetch_db(int fd, uint32_t nonce);
  int handle_packet_fetch_track(int fd, uint32_t nonce, const std::string req);
  int handle_packet_fetch_image(int fd, uint32_t nonce, const std::string req);
  int handle_packet(int fd, uint32_t nonce, PacketOpcode cmd,
                    std::string &data);

protected:
  std::string cache_path(const std::string &hash);
  void queue_transcode_for_socket_nonce(int fd, uint32_t nonce,
                                        const std::string &hash);
  void transcode_worker_loop();

protected:
  void add_pollfd(int fd);
  void remove_pollfd(int index);

private:
  const Settings _settings;

  // Client socket state
  std::vector<struct pollfd> _pollfds;
  std::vector<std::string> _slabs;

  // PSQL connections
  pqxx::connection _pq_conn;
  pqxx::connection _db_update_pq_conn;

  // Database updates are very slow, run in a separate thread
  std::atomic<bool> _db_thread_update_request{false};
  std::thread _db_update_thread;

  // Transcode request data
  std::mutex _transcode_queue_mutex;
  std::condition_variable _transcode_queue_cv;
  std::deque<TranscodeJob> _transcode_request_queue;
  std::deque<TranscodeJob> _transcode_response_queue;

  // Transcoding threadpool
  static const int TRANSCODE_THREADPOOL_SIZE = 8;
  ThreadPool _transcode_threadpool;
};

int set_socket_nonblocking(int fd);
int set_socket_keepalive(int fd, int interval, int tolerance);

} // namespace musicd
