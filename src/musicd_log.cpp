#include <stdarg.h>
#include <time.h>

#include <musicd/log.hpp>

namespace musicd {
namespace log {

static const char *COLOUR_NONE = "\x1B[0m";
static const char *COLOUR_RED = "\x1B[31m";
static const char *COLOUR_GRN = "\x1B[32m";
static const char *COLOUR_YEL = "\x1B[33m";
static const char *COLOUR_CYN = "\x1B[36m";

void write(const char *filename, int line, LogLevel level, const char *fmt,
           ...) {

  // Format timestamp
  char time_buffer[32];
  time_t system_time;
  ::time(&system_time);
  struct tm *timeinfo;
  timeinfo = localtime(&system_time);
  strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

  // Set the tag colours (if applicable)
  const char *colour_tag = COLOUR_NONE;
  const char *severity_str = "UNKNOWN";
  switch (level) {
  case LogLevel::INFO:
    colour_tag = COLOUR_GRN;
    severity_str = "INFO";
    break;
  case LogLevel::WARN:
    colour_tag = COLOUR_YEL;
    severity_str = "WARN";
    break;
  case LogLevel::ERROR:
    colour_tag = COLOUR_RED;
    severity_str = "ERROR";
    break;
  }

  // Print log leader
  fprintf(stderr, "[%s%s%s][%s%s%s][%s%s:%d%s] ",
          // Time colour & value
          COLOUR_GRN, time_buffer, COLOUR_NONE,
          // Tag colour & value
          colour_tag, severity_str, COLOUR_NONE,
          // File name / line
          COLOUR_CYN, filename, line, COLOUR_NONE);

  // Pull out our varargs format values
  va_list args;
  va_start(args, fmt);
  // Actual log info
  vfprintf(stderr, fmt, args);
  // Finish our varargs
  va_end(args);
}

} // namespace log
} // namespace musicd

