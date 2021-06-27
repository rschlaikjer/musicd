#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <Magick++.h>

#include <musicd/db.hpp>
#include <musicd/log.hpp>
#include <musicd/net.hpp>
#include <musicd/transcode.hpp>

template <typename T> void remove_in_vector(std::vector<T> &v, int idx) {
  v[idx].swap(v.back());
  v.pop_back();
}

template <>
void remove_in_vector<struct pollfd>(std::vector<struct pollfd> &v, int idx) {
  v[idx] = v.back();
  v.pop_back();
}

namespace musicd {

void NetServer::add_pollfd(int fd) {
  _pollfds.emplace_back();
  _pollfds.back().fd = fd;
  _pollfds.back().events = POLLIN;
  _slabs.emplace_back();
};

void NetServer::remove_pollfd(int index) {
  remove_in_vector(_pollfds, index);
  remove_in_vector(_slabs, index);
};

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

void NetServer::queue_transcode_for_socket_nonce(int fd, uint32_t nonce,
                                                 const std::string &hash) {

  // Lock the transcode queue
  std::unique_lock<std::mutex> lock(_transcode_queue_mutex);

  // Emplace the job
  TranscodeJob job;
  job.fd = fd;
  job.nonce = nonce;
  job.hash = hash;
  job.input_path = fetch_track_path_by_checksum(_pq_conn, job.hash);
  _transcode_request_queue.emplace_back(job);

  // Notify a worker
  _transcode_queue_cv.notify_one();
}

void NetServer::transcode_worker_loop() {
  while (true) {

    // If there is an entry we can process, pop it
    TranscodeJob job;
    {
      // Lock the transcode queue
      std::unique_lock<std::mutex> lock(_transcode_queue_mutex);
      if (_transcode_request_queue.size() > 0) {
        job = _transcode_request_queue.front();
        _transcode_request_queue.pop_front();
      } else {
        // Wait for something to get enqueued
        _transcode_queue_cv.wait(lock);
        continue;
      }
    }

    // If we got a job to process, go transcode it
    LOG_I("Worker received transcode job for content hash %s\n",
          bytes_to_hex(job.hash).c_str());

    // Generate the cache file path
    const std::string transcode_path = cache_path(job.hash);

    // Go transcode the file
    const bool transcode_ok =
        transcode_track(job.input_path.c_str(), transcode_path.c_str());
    job.success = transcode_ok;
    LOG_I("Transcode %s for source track %s\n", transcode_ok ? "OK" : "FAILURE",
          job.input_path.c_str());

    // Put the job on the output queue
    {
      std::unique_lock<std::mutex> lock(_transcode_queue_mutex);
      _transcode_response_queue.emplace_back(job);
    }
  }
}

NetServer::NetServer(Settings settings)
    : _settings(settings), _transcode_queue_mutex(), _transcode_queue_cv(),
      _transcode_threadpool(
          TRANSCODE_THREADPOOL_SIZE,
          std::bind(&NetServer::transcode_worker_loop, this)) {

  // Prepare PQ connection
  pq_prepare(_pq_conn);

  // Spawn db update thread
  _db_update_thread = std::thread([&]() {
    while (true) {
      if (_db_thread_update_request.exchange(false)) {
        update_db(_pq_conn, _settings.music_dir.c_str());
      }
      usleep(1'000'000);
    }
  });
}

NetServer::~NetServer() {}

bool NetServer::init() {
  // Ensure cache dir exists
  if (!std::filesystem::exists(_settings.cache_dir)) {
    if (!std::filesystem::create_directories(_settings.cache_dir)) {
      LOG_E("Failed to create cache directory %s\n",
            _settings.cache_dir.c_str());
      return false;
    }
  }

  // Try and resolve the bind address / port
  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  struct addrinfo *servinfo;
  int err = getaddrinfo(_settings.bind_addr.c_str(),
                        _settings.bind_port.c_str(), &hints, &servinfo);
  if (err != 0) {
    LOG_E("getaddrinfo: %s\n", gai_strerror(err));
    return false;
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
    LOG_E("failed to bind to %s: %s\n", _settings.bind_addr.c_str(),
          _settings.bind_port.c_str());
    return false;
  }

  // Enable listen
  if (listen(sockfd, /* backlog */ 64) == -1) {
    LOG_E("listen: %s\n", strerror(errno));
    return false;
  }

  // Nonblocking
  if (set_socket_nonblocking(sockfd)) {
    return false;
  }

  // Socket is up
  LOG_I("%s: %s: listening\n", _settings.bind_addr.c_str(),
        _settings.bind_port.c_str());
  add_pollfd(sockfd);

  return true;
}

int NetServer::send_packet_response(int fd, uint32_t nonce, PacketOpcode opcode,
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
  LOG_I("Send response of size %lu on fd %d for nonce %08x\n", data.size(), fd,
        nonce);

  return total_sent;
}

int NetServer::handle_packet_update_db(int fd, uint32_t nonce) {
  LOG_I("Update db for fd %d\n", fd);
  _db_thread_update_request.store(true);
  std::string empty = "";
  return send_packet_response(fd, nonce, PacketOpcode::UPDATE_REMOTE_DB, empty);
}

int NetServer::handle_packet_fetch_db(int fd, uint32_t nonce) {
  LOG_I("Fetch db for fd %d\n", fd);
  // Serialize database to pb
  std::unique_ptr<msgs::MusicDatabase> db = serialize_music_db(_pq_conn);

  // Send our response
  std::string pb_data;
  db->SerializeToString(&pb_data);

  LOG_I("Serialized DB size: %lu\n", pb_data.size());
  return send_packet_response(fd, nonce, PacketOpcode::FETCH_DB, pb_data);
}

std::string NetServer::cache_path(const std::string &hash) {
  std::filesystem::path path(_settings.cache_dir);
  path.append(bytes_to_hex(hash));
  return path;
}

int NetServer::handle_packet_fetch_track(int fd, uint32_t nonce,
                                         const std::string req) {
  const std::string content_id_hex = bytes_to_hex(req);
  LOG_I("Fetch track %s for fd %d\n", content_id_hex.c_str(), fd);

  // Does there exist a cached transcode of this track?
  const std::string transcode_path = cache_path(req);
  if (std::filesystem::exists(transcode_path)) {
    // If it does, send it
    std::unique_ptr<std::string> cached_data = read_file(transcode_path);
    LOG_I("Sending cached response for track %s size %lu\n",
          content_id_hex.c_str(), cached_data->size());
    return send_packet_response(fd, nonce, PacketOpcode::FETCH_TRACK,
                                *cached_data);
  }

  // Does this content hash map to a file in the DB at all?
  std::string track_path = fetch_track_path_by_checksum(_pq_conn, req);
  if (track_path.empty()) {
    std::string empty_resp = "";
    LOG_E("Failed to find track for checksum %s\n", content_id_hex.c_str());
    return send_packet_response(fd, nonce, PacketOpcode::FETCH_TRACK,
                                empty_resp);
  }

  // If the source file is valid, queue a transcode op
  LOG_I("Queueing transcode operation for fd %d, nonce %08x, track %s\n", fd,
        nonce, track_path.c_str());
  queue_transcode_for_socket_nonce(fd, nonce, req);

  return 0;
}

int NetServer::handle_packet_fetch_image(int fd, uint32_t nonce,
                                         const std::string req) {
  LOG_I("Fetch image %s for fd %d\n", bytes_to_hex(req).c_str(), fd);

  // Try and fetch a image with this checksum
  std::unique_ptr<std::string> image_data =
      fetch_image_by_checksum(_pq_conn, req);

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

int NetServer::handle_packet(int fd, uint32_t nonce, PacketOpcode cmd,
                             std::string &data) {
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

int NetServer::process_incoming_data(int fd, std::string &slab) {
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

int NetServer::loop() {
  while (true) {
    int event_count =
        poll(_pollfds.data(), _pollfds.size(), /* timeout */ 1000);
    if (event_count < 0) {
      LOG_E("Poll error: %d: %s\n", errno, strerror(errno));
      continue;
    }

    // Check if any transcode ops completed and need to be dispatched
    {
      std::unique_lock<std::mutex> lock(_transcode_queue_mutex);
      while (!_transcode_response_queue.empty()) {
        TranscodeJob job = _transcode_response_queue.front();
        _transcode_response_queue.pop_front();

        if (job.success) {
          // Look up the fd, and if it's still valid, send the response data
          std::unique_ptr<std::string> cached_data =
              read_file(cache_path(job.hash));
          send_packet_response(job.fd, job.nonce, PacketOpcode::FETCH_TRACK,
                               *cached_data);
        } else {
          // Send the un-transcoded source file as a fallback
          std::unique_ptr<std::string> track_data = read_file(job.input_path);
          send_packet_response(job.fd, job.nonce, PacketOpcode::FETCH_TRACK,
                               *track_data);
        }
      }
    }

    for (unsigned i = 0; i < _pollfds.size(); i++) {
      if (i == 0) {
        // Listen socket
        // Handle the listening socket.
        if (_pollfds[i].revents & POLLERR) {
          LOG_E("Poll error for listen fd: %d: %s\n", errno, strerror(errno));
          return EXIT_FAILURE;
        }

        struct sockaddr_storage their_addr = {};
        socklen_t ss_size = sizeof(their_addr);
        int conn_fd =
            accept(_pollfds[i].fd, (struct sockaddr *)&their_addr, &ss_size);
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
        if (_pollfds[i].revents & (POLLERR | POLLHUP)) {
          // Socket problem, disconnect them
          LOG_I("Poll error for fd %d\n", _pollfds[i].fd);
          close(_pollfds[i].fd);
          remove_pollfd(i);
          continue;
        }

        // Try and consume socket data
        char buf[1024];
        int read_size;
        do {
          read_size = read(_pollfds[i].fd, buf, sizeof(buf));
          if (read_size > 0) {
            _slabs[i].append(buf, read_size);
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              // Fine
              break;
            } else {
              LOG_E("read fd %d: %d: %s\n", _pollfds[i].fd, errno,
                    strerror(errno));
              close(_pollfds[i].fd);
              remove_pollfd(i);

              goto CONTINUE;
            }
          }
        } while (read_size);

        // If we didn't hit an error, we must have read data, so go process
        // the current slab
        int process_ok;
        while ((process_ok = process_incoming_data(_pollfds[i].fd, _slabs[i])) >
               0) {
        }
        if (process_ok < 0) {
          LOG_E("Error processing packets on fd %d, closing\n", _pollfds[i].fd);
          close(_pollfds[i].fd);
          remove_pollfd(i);
        }
      CONTINUE:
        continue;
      }
    }
  }

  return EXIT_SUCCESS;
}

} // namespace musicd
