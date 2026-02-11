#ifndef FUZZ_INPUT_H
#define FUZZ_INPUT_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static bool fuzz_read_file_bounded(const char *path, size_t max_bytes,
                                   uint8_t **out_data, size_t *out_size) {
  if (path == nullptr || out_data == nullptr || out_size == nullptr) {
    return false;
  }
  *out_data = nullptr;
  *out_size = 0U;

  FILE *file = fopen(path, "rb");
  if (file == nullptr) {
    return false;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return false;
  }
  long end = ftell(file);
  if (end < 0) {
    fclose(file);
    return false;
  }
  if (fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return false;
  }

  uintmax_t end_umax = (uintmax_t)end;
  if (end_umax > (uintmax_t)max_bytes || end_umax > (uintmax_t)SIZE_MAX) {
    fclose(file);
    return false;
  }

  size_t size = (size_t)end_umax;
  if (size == 0U) {
    fclose(file);
    return true;
  }

  uint8_t *data = calloc(size, sizeof(uint8_t));
  if (data == nullptr) {
    fclose(file);
    return false;
  }

  size_t read = fread(data, sizeof(uint8_t), size, file);
  fclose(file);
  if (read != size) {
    free(data);
    return false;
  }

  *out_data = data;
  *out_size = size;
  return true;
}

#endif
