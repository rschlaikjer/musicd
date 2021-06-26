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
  if (argc != 3) {
    fprintf(stderr, "Usage: %s [Music Dir] [Cache Dir]\n", argv[0]);
    return EXIT_FAILURE;
  }

  // Init imagemagick
  Magick::InitializeMagick(*argv);

  // Server settings
  NetServer::Settings settings;
  settings.bind_addr = "0.0.0.0";
  settings.bind_port = "5959";
  settings.music_dir = argv[1];
  settings.cache_dir = argv[2];

  // Try and init the net server loop
  NetServer server(settings);
  if (!server.init()) {
    return EXIT_FAILURE;
  }

  // Run the server forever
  return server.loop();
}
