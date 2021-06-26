#pragma once

#include <poll.h>
#include <stdint.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include <pqxx/pqxx>

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

  NetServer(const char *bind, const char *port, const char *music_dir);
  ~NetServer();

  bool init();
  int loop();

protected:
  int process_incoming_data(int fd, std::string &slab);
  int send_packet_response(int fd, uint32_t nonce, PacketOpcode opcode,
                           std::string &data);
  int handle_packet_update_db(int fd, uint32_t nonce);
  int handle_packet_fetch_db(int fd, uint32_t nonce);
  int handle_packet_fetch_track(int fd, uint32_t nonce, std::string req);
  int handle_packet_fetch_image(int fd, uint32_t nonce, std::string req);
  int handle_packet(int fd, uint32_t nonce, PacketOpcode cmd,
                    std::string &data);

protected:
  void add_pollfd(int fd);
  void remove_pollfd(int index);

private:
  const std::string _bind_addr;
  const std::string _listen_port;
  const std::string _music_basedir;

  std::vector<struct pollfd> _pollfds;
  std::vector<std::string> _slabs;

  // Prepare PG connection
  pqxx::connection _pq_conn;

  // Database updates are very slow, run in a separate thread
  std::atomic<bool> _db_thread_update_request{false};
  std::thread _db_update_thread;
};

int set_socket_nonblocking(int fd);
int set_socket_keepalive(int fd, int interval, int tolerance);

} // namespace musicd
