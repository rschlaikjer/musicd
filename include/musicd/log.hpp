#pragma once

#include <stdio.h>

#define LOG_I(fmt, ...)                                                        \
  ::musicd::log::write(__FILE__, __LINE__, ::musicd::log::LogLevel::INFO, fmt, \
                       ##__VA_ARGS__)
#define LOG_W(fmt, ...)                                                        \
  ::musicd::log::write(__FILE__, __LINE__, ::musicd::log::LogLevel::WARN, fmt, \
                       ##__VA_ARGS__)
#define LOG_E(fmt, ...)                                                        \
  ::musicd::log::write(__FILE__, __LINE__, ::musicd::log::LogLevel::ERROR,     \
                       fmt, ##__VA_ARGS__)

namespace musicd {
namespace log {

enum LogLevel {
  INFO,
  WARN,
  ERROR,
};

void write(const char *file, int line, LogLevel level, const char *fmt, ...);

} // namespace log
} // namespace musicd
