#include <pqxx/pqxx>

#include <Magick++.h>

#include <musicd/net.hpp>

using namespace musicd;

void pgusage() {
  fprintf(stderr,
          "PSQL variables not set! Please ensure the following are defined:\n"
          "PGHOST (db host)\n"
          "PGDATABASE (database)\n"
          "PGUSER (username)\n"
          "PGPASSWORD (password)\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  // Check that postgres variables are present
  if (!getenv("PGHOST") || !getenv("PGDATABASE") || !getenv("PGUSER") ||
      !getenv("PGPASSWORD")) {
    pgusage();
  }

  // Check args
  if (argc != 2) {
    fprintf(stderr, "Usage: %s [Music Dir]\n", argv[0]);
  }
  const char *music_basedir = argv[1];

  // Init imagemagick
  Magick::InitializeMagick(*argv);

  // Try and init the net server loop
  const char *bind_addr = "0.0.0.0";
  const char *bind_port = "5959";
  NetServer server(bind_addr, bind_port, music_basedir);
  if (!server.init()) {
    return EXIT_FAILURE;
  }

  // Run the server forever
  return server.loop();
}
