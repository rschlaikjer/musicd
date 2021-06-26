#pragma once

namespace musicd {
void print_transcode_versions();
bool transcode_track(const char *input_file, const char *output_file);
} // namespace musicd
