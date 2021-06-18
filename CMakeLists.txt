cmake_minimum_required(VERSION 3.1)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/;/usr/local/")

if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(SEND_ERROR "In-source builds are not allowed.")
endif ()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE ON)

set(CMAKE_CXX_STANDARD 17)

if (CMAKE_BUILD_TYPE MATCHES Debug)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -gdwarf-4 -g3 -g -rdynamic")
  set(GCC_OPTIMIZATION "-O0")
endif ()

set(GCC_COVERAGE_COMPILE_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas -Werror -Wno-error=unused-variable -Wno-error=unused-but-set-variable -Wno-error=pragmas -Wno-error=unused-local-typedefs")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS} ${GCC_OPTIMIZATION}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")

project(musicd LANGUAGES C CXX)

find_package(PkgConfig)
pkg_check_modules(PC_LIBTAG REQUIRED taglib)
include_directories(${PC_LIBTAG_INCLUDE_DIRS})

pkg_check_modules(PC_LIBPQ REQUIRED libpqxx)
include_directories(${PC_LIBPQ_INCLUDE_DIRS})

INCLUDE(FindProtobuf)
FIND_PACKAGE(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

INCLUDE(FindImageMagick)
FIND_PACKAGE(ImageMagick REQUIRED COMPONENTS Magick++)
include_directories(${ImageMagick_INCLUDE_DIRS})

pkg_check_modules(LIBAV_FORMAT REQUIRED libavformat)
pkg_check_modules(LIBAV_CODEC REQUIRED libavcodec)
pkg_check_modules(LIBAV_UTIL REQUIRED libavutil)
include_directories(${LIBAV_FORMAT_INCLUDE_DIRS})
include_directories(${LIBAV_CODEC_INCLUDE_DIRS})
include_directories(${LIBAV_UTIL_INCLUDE_DIRS})

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS
    ${CMAKE_CURRENT_SOURCE_DIR}/pb/track.proto)

add_executable(musicd
  src/musicd.cpp
  ${PROTO_SRCS}
  ${PROTO_HDRS}
)
target_compile_definitions(musicd
    PUBLIC -DMAGICKCORE_QUANTUM_DEPTH=16
    PUBLIC -DMAGICKCORE_HDRI_ENABLE=false
)
target_link_libraries(musicd
  stdc++fs
  ${PC_LIBTAG_LIBRARIES}
  ${PC_LIBPQ_LIBRARIES}
  ${Protobuf_LIBRARIES}
  ${ImageMagick_LIBRARIES}
  ssl
  crypto
  ${LIBAV_FORMAT_LIBRARIES}
  ${LIBAV_CODEC_LIBRARIES}
  ${LIBAV_UTIL_LIBRARIES}
)
