#include <memory>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/opt.h>
#include <libswresample/swresample.h>
}

#include <lame/lame.h>

#include <musicd/log.hpp>
#include <musicd/transcode.hpp>

namespace musicd {

void print_transcode_versions() {
  LOG_I("avformat: version %u\n", avformat_version());
  LOG_I("avcodec version %u\n", avcodec_version());
  LOG_I("avutil version %u\n", avutil_version());
  LOG_I("swresample version %u\n", swresample_version());
}

void print_av_err(const char *msg, int err) {
  if (err) {
    char err_buf[AV_ERROR_MAX_STRING_SIZE];
    av_strerror(err, err_buf, sizeof(err_buf));
    LOG_E("%s: %d: %s\n", msg, err, err_buf);
  }
}

bool av_decode_to_fifo(const char *input_path, AVAudioFifo **fifo) {
  // Create an avformat context
  AVFormatContext *decoder_avfc = avformat_alloc_context();
  if (decoder_avfc == nullptr) {
    LOG_E("Failed to create decoder avformat context\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_avfc(nullptr, [&](...) {
    if (decoder_avfc != nullptr) {
      avformat_free_context(decoder_avfc);
    }
  });

  // Attempt to open the source track
  int err = avformat_open_input(&decoder_avfc, input_path,
                                /* autodetect format */ nullptr,
                                /* options */ nullptr);
  if (err < 0) {
    print_av_err("avformat_open_input", err);
    return false;
  }
  std::shared_ptr<void> _defer_close_input(
      nullptr, [&](...) { avformat_close_input(&decoder_avfc); });

  // Detect streams
  err = avformat_find_stream_info(decoder_avfc, nullptr);
  if (err < 0) {
    print_av_err("avformat_find_stream_info", err);
    return false;
  }

  // Locate the first audio stream
  int source_stream_index = -1;
  for (int i = 0; i < (int)decoder_avfc->nb_streams; i++) {
    if (decoder_avfc->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
      if (source_stream_index >= 0) {
        LOG_E("Source file contains more than one audio track - not sure how "
              "to proceed\n");
        return false;
      }
      source_stream_index = i;
    }
  }

  // Did we find exactly one audio stream?
  if (source_stream_index < 0) {
    LOG_E("Failed to locate input audio stream\n");
    return false;
  }

  // Generate a decoder for this stream
  AVCodec *decoder_codec = avcodec_find_decoder(
      decoder_avfc->streams[source_stream_index]->codecpar->codec_id);
  if (decoder_codec == nullptr) {
    LOG_E("Failed to locate codec for input audio stream\n");
    return false;
  }

  // Create a decode codec context
  AVCodecContext *decoder_avcc = avcodec_alloc_context3(decoder_codec);
  if (decoder_avcc == nullptr) {
    LOG_E("Failed to create decoder AVCodec context\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_avcc(
      nullptr, [&](...) { avcodec_free_context(&decoder_avcc); });

  // Load codec parameters
  if ((err = avcodec_parameters_to_context(
           decoder_avcc,
           decoder_avfc->streams[source_stream_index]->codecpar)) < 0) {
    print_av_err("avcodec_parameters_to_context", err);
    return false;
  }

  // Open the codec
  if ((err = avcodec_open2(decoder_avcc, decoder_codec, nullptr)) < 0) {
    print_av_err("avcodec_open2", err);
    return false;
  }

  // Create an audio FIFO to hold the decoded stream
  const AVSampleFormat raw_sample_fmt = AV_SAMPLE_FMT_FLTP;
  const int channels =
      decoder_avfc->streams[source_stream_index]->codecpar->channels;
  AVAudioFifo *audio_fifo = av_audio_fifo_alloc(raw_sample_fmt, channels, 1);
  if (audio_fifo == nullptr) {
    LOG_E("Failed to create audio FIFO\n");
    return false;
  }

  // If our decoder doesn't output FLTP samples, we need to create a resampler
  const AVCodecParameters *input_codecpar =
      decoder_avfc->streams[source_stream_index]->codecpar;
  const AVSampleFormat input_sample_format = static_cast<AVSampleFormat>(
      decoder_avfc->streams[source_stream_index]->codecpar->format);
  const bool must_resample = input_sample_format != raw_sample_fmt;
  if (must_resample) {
    LOG_I("Resampling input %s from %s to %s\n", input_path,
          av_get_sample_fmt_name(input_sample_format),
          av_get_sample_fmt_name(raw_sample_fmt));
  }

  // Initialize the SWR context if needed
  SwrContext *swr = nullptr;
  std::shared_ptr<void> _defer_free_swr;
  static const int RESAMPLE_BUFFER_SIZE_SAMPLES = 8192;
  float *resampled[8] = {nullptr};
  if (must_resample) {
    swr = swr_alloc();
    av_opt_set_int(swr, "in_channel_layout", input_codecpar->channel_layout, 0);
    av_opt_set_int(swr, "out_channel_layout", input_codecpar->channel_layout,
                   0);
    av_opt_set_int(swr, "in_sample_rate", input_codecpar->sample_rate, 0);
    av_opt_set_int(swr, "out_sample_rate", 44100, 0);
    av_opt_set_sample_fmt(swr, "in_sample_fmt", input_sample_format, 0);
    av_opt_set_sample_fmt(swr, "out_sample_fmt", raw_sample_fmt, 0);
    swr_init(swr);

    // Allocate intermediate buffer for resampled data
    const int buffer_size = av_samples_get_buffer_size(
        nullptr, input_codecpar->channels, RESAMPLE_BUFFER_SIZE_SAMPLES,
        raw_sample_fmt, 1);
    for (int i = 0; i < input_codecpar->channels; i++) {
      resampled[i] = static_cast<float *>(malloc(buffer_size));
    }

    // Ensure all resampling related data is cleaned up later
    _defer_free_swr = std::shared_ptr<void>(nullptr, [&](...) {
      // Free swresample context
      swr_free(&swr);
      // Free all of the intermediate buffers
      for (int i = 0; i < input_codecpar->channels; i++) {
        free(resampled[i]);
      }
    });
  }

  // Create input frame holder
  AVFrame *input_frame = av_frame_alloc();
  if (input_frame == nullptr) {
    LOG_E("Failed to allocate input frame\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_input_frame =
      std::shared_ptr<void>(nullptr, [&](...) { av_frame_free(&input_frame); });

  // Create input packet holder
  AVPacket *input_packet = av_packet_alloc();
  if (input_packet == nullptr) {
    LOG_E("Failed to allocate input packet\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_input_packet = std::shared_ptr<void>(
      nullptr, [&](...) { av_packet_free(&input_packet); });

  // Consume the decoder context until we hit EOF
  while (av_read_frame(decoder_avfc, input_packet) >= 0) {
    // Ensure packet gets unref'd when done
    std::shared_ptr<void> _defer_unref_packet = std::shared_ptr<void>(
        nullptr, [=](...) { av_packet_unref(input_packet); });

    int response = avcodec_send_packet(decoder_avcc, input_packet);
    while (response >= 0) {
      response = avcodec_receive_frame(decoder_avcc, input_frame);
      if (response == AVERROR(EAGAIN) || response == AVERROR_EOF) {
        break;
      } else if (response < 0) {
        print_av_err("avcodec_receive_frame", response);
        return false;
      }

      // If the input codec is not already using FLTP samples, we need to
      // resample it
      if (must_resample) {
        if (input_frame->nb_samples > RESAMPLE_BUFFER_SIZE_SAMPLES) {
          LOG_E("Attempted to resample %d samples into buffer sized for %d "
                "samples!\n",
                input_frame->nb_samples, RESAMPLE_BUFFER_SIZE_SAMPLES);
        }
        swr_convert(swr, (uint8_t **)resampled, input_frame->nb_samples,
                    (const uint8_t **)input_frame->data,
                    input_frame->nb_samples);

        av_audio_fifo_write(audio_fifo, /* data */ (void **)resampled,
                            /*nb_samples*/ input_frame->nb_samples);
      } else {
        av_audio_fifo_write(audio_fifo, /* data */ (void **)input_frame->data,
                            /*nb_samples*/ input_frame->nb_samples);
      }
    }
  }

  // Done decoding the input data
  *fifo = audio_fifo;
  return true;
}

bool av_encode_from_fifo(AVAudioFifo *audio_fifo, const char *output_path) {
  // Locate the MP3 encoder
  AVCodec *mp3_codec = avcodec_find_encoder(AVCodecID::AV_CODEC_ID_MP3);
  if (mp3_codec == nullptr) {
    LOG_E("Failed to load MP3 encoder\n");
    return false;
  }

  // Create an avcodec context using the MP3 encoder
  AVCodecContext *avcc = avcodec_alloc_context3(mp3_codec);
  if (avcc == nullptr) {
    LOG_E("Failed to create avcodec context\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_avcc(
      nullptr, [&](...) { avcodec_free_context(&avcc); });

  // Set up the output codec params
  avcc->codec_type = AVMEDIA_TYPE_AUDIO;
  avcc->channels = 2;
  avcc->channel_layout = av_get_default_channel_layout(avcc->channels);
  avcc->sample_fmt = AV_SAMPLE_FMT_FLTP;
  avcc->sample_rate = 44100;
  avcc->time_base = AVRational{1, avcc->sample_rate};
  // VBR V0
  avcc->flags |= AV_CODEC_FLAG_QSCALE;
  avcc->global_quality = V0;

  // Try and open the codec
  int err;
  if ((err = avcodec_open2(avcc, mp3_codec, nullptr)) < 0) {
    print_av_err("avcodec_open2", err);
    return false;
  }

  // Create an output context
  AVFormatContext *encoder_avfc;
  avformat_alloc_output_context2(&encoder_avfc, nullptr, "mp3", output_path);
  if (encoder_avfc == nullptr) {
    LOG_E("Failed to create encoder output format context\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_encoder_avfc = std::shared_ptr<void>(
      nullptr, [&](...) { avformat_free_context(encoder_avfc); });

  // Create a stream in that context
  AVStream *output_stream = avformat_new_stream(encoder_avfc, nullptr);
  if ((err = avcodec_parameters_from_context(output_stream->codecpar, avcc)) <
      0) {
    print_av_err("avcodec_paramters_from_context", err);
    return false;
  }

  // Ensure that a global header gets written if necessary
  if (encoder_avfc->oformat->flags & AVFMT_GLOBALHEADER) {
    encoder_avfc->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
  }

  // Try and create the output file
  std::shared_ptr<void> _defer_avio_close;
  if (!(encoder_avfc->oformat->flags & AVFMT_NOFILE)) {
    if ((err = avio_open(&encoder_avfc->pb, output_path, AVIO_FLAG_WRITE)) <
        0) {
      print_av_err("avio_open", err);
      return false;
    }

    // Defer close
    _defer_avio_close = std::shared_ptr<void>(
        nullptr, [&](...) { avio_close(encoder_avfc->pb); });
  }

  // Write the output header
  if ((err = avformat_write_header(encoder_avfc, nullptr)) < 0) {
    print_av_err("avformat_write_header", err);
    return false;
  }

  // Create an output packet holder
  AVPacket *output_packet = av_packet_alloc();
  if (output_packet == nullptr) {
    LOG_E("Failed to allocate output packet\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_output_packet(
      nullptr, [&](...) { av_packet_free(&output_packet); });

  // Create an input frame
  AVFrame *input_frame = av_frame_alloc();
  if (input_frame == nullptr) {
    LOG_E("Failed to allocate input frame\n");
    return false;
  }
  std::shared_ptr<void> _defer_free_input_frame(
      nullptr, [&](...) { av_frame_free(&input_frame); });

  // Initialize input frame
  static const int INPUT_SAMPLES = 1024;
  input_frame->nb_samples = INPUT_SAMPLES;
  input_frame->channel_layout = avcc->channel_layout;
  input_frame->format = avcc->sample_fmt;
  input_frame->sample_rate = avcc->sample_rate;
  if ((err = av_frame_get_buffer(input_frame, 0)) < 0) {
    print_av_err("av_frame_get_buffer", err);
    return false;
  }

  // Stream data from the FIFO into the encoder context
  int pts = 0;
  while (av_audio_fifo_size(audio_fifo)) {
    // Try and read some data from the FIFO
    const int samples_to_read = INPUT_SAMPLES;
    int err = av_audio_fifo_read(audio_fifo, (void **)input_frame->data,
                                 samples_to_read);
    if (err < 0) {
      print_av_err("av_audio_fifo_read", err);
      return false;
    }

    // Input frame pts/dts accounting
    input_frame->pts = pts;
    pts += err;

    // Send that data to the encoder
    int response = avcodec_send_frame(avcc, input_frame);
    while (response >= 0) {
      response = avcodec_receive_packet(avcc, output_packet);
      if (response == AVERROR(EAGAIN) || response == AVERROR_EOF) {
        break;
      } else if (response < 0) {
        print_av_err("avcodec_receive_packet", response);
        return false;
      }

      response = av_interleaved_write_frame(encoder_avfc, output_packet);
      if (response != 0) {
        print_av_err("av_interleaved_write_frame", response);
        return false;
      }
    }
  }

  // Flush the encoder
  int response = avcodec_send_frame(avcc, nullptr);
  while (response >= 0) {
    response = avcodec_receive_packet(avcc, output_packet);
    if (response == AVERROR(EAGAIN) || response == AVERROR_EOF) {
      break;
    } else if (response < 0) {
      print_av_err("avcodec_receive_packet", response);
      return false;
    }

    response = av_interleaved_write_frame(encoder_avfc, output_packet);
    if (response != 0) {
      print_av_err("av_interleaved_write_frame", response);
      return false;
    }
  }

  // Finalize the output file
  av_write_trailer(encoder_avfc);

  return true;
}

bool transcode_track(const char *input_path, const char *output_path) {
  // Attempt to load the input audio to a FIFO
  AVAudioFifo *audio_fifo;
  if (!av_decode_to_fifo(input_path, &audio_fifo)) {
    return false;
  }
  std::shared_ptr<void> _defer_free_audio_fifo = std::shared_ptr<void>(
      nullptr, [&](...) { av_audio_fifo_free(audio_fifo); });

  // Try and encode the buffered data
  return av_encode_from_fifo(audio_fifo, output_path);
}

} // namespace musicd
