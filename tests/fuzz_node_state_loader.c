#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzz_input.h"

#define main nano_node_cli_main
#include "../src/nano_node.c"
#undef main

static constexpr size_t NODE_STATE_FUZZ_MAX_INPUT_BYTES = 1U * 1'024U * 1'024U;

static bool write_temp_state_file(const uint8_t *data, size_t size,
                                  char out_path[static 64]) {
  static constexpr char template_path[] = "/tmp/nano-node-fuzz-XXXXXX";
  memcpy(out_path, template_path, sizeof(template_path));

  int fd = mkstemp(out_path);
  if (fd < 0) {
    return false;
  }

  FILE *file = fdopen(fd, "wb");
  if (file == nullptr) {
    close(fd);
    (void)unlink(out_path);
    return false;
  }

  bool ok = true;
  if (size > 0U && data == nullptr) {
    ok = false;
  }
  if (ok && size > 0U && fwrite(data, sizeof(uint8_t), size, file) != size) {
    ok = false;
  }
  if (fclose(file) != 0) {
    ok = false;
  }

  if (!ok) {
    (void)unlink(out_path);
  }
  return ok;
}

static void fuzz_node_state_bytes(const uint8_t *data, size_t size) {
  if (size > NODE_STATE_FUZZ_MAX_INPUT_BYTES) {
    return;
  }

  char path[64];
  if (!write_temp_state_file(data, size, path)) {
    return;
  }

  NodeState state;
  if (node_state_load(path, &state)) {
    node_state_destroy(&state);
  }
  (void)unlink(path);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_node_state_bytes(data, size);
  return 0;
}

int main(int argc, char **argv) {
  // Avoid large error output for expected-invalid fuzz cases.
  (void)freopen("/dev/null", "w", stderr);

  for (int i = 1; i < argc; ++i) {
    uint8_t *data = nullptr;
    size_t size = 0U;
    if (!fuzz_read_file_bounded(argv[i], NODE_STATE_FUZZ_MAX_INPUT_BYTES, &data,
                                &size)) {
      continue;
    }
    (void)LLVMFuzzerTestOneInput(data, size);
    free(data);
  }
  return 0;
}
