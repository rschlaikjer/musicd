#pragma once

#include <stdio.h>

#define LOG_I(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
