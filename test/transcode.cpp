#include <stdio.h>
#include <stdlib.h>

#include <musicd/transcode.hpp>

int main(int argc, char **argv) {
  // Args
  if (argc != 3) {
    fprintf(stderr, "%s [input] [output]\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char *input_file = argv[1];
  const char *output_file = argv[2];

  musicd::transcode_track(input_file, output_file);
  return EXIT_SUCCESS;
}
