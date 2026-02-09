#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "evm/return_data_internal.h"
#include "evm/state_internal.h"

void clear_return_data(EVM_State *vm) {
  free(vm->return_data);
  vm->return_data = nullptr;
  vm->return_data_size = 0;
}

EVM_Status copy_memory_slice(EVM_State *vm, size_t offset, size_t size,
                                    uint8_t **out_data) {
  if (size == 0) {
    *out_data = nullptr;
    return EVM_OK;
  }

  size_t end = 0;
  if (add_size_overflow(offset, size, &end)) {
    return EVM_ERR_RUNTIME;
  }

  EVM_Status status = evm_memory_ensure(vm, end);
  if (status != EVM_OK) {
    return status;
  }

  uint8_t *data = calloc(size, sizeof(uint8_t));
  if (data == nullptr) {
    return EVM_ERR_OOM;
  }
  memcpy(data, vm->memory + offset, size);
  *out_data = data;
  return EVM_OK;
}

EVM_Status set_return_data(EVM_State *vm, size_t offset, size_t size) {
  clear_return_data(vm);

  uint8_t *data = nullptr;
  EVM_Status status = copy_memory_slice(vm, offset, size, &data);
  if (status != EVM_OK) {
    return status;
  }

  vm->return_data = data;
  vm->return_data_size = size;
  return EVM_OK;
}

EVM_Status set_return_data_bytes(EVM_State *vm, const uint8_t *data,
                                        size_t size) {
  clear_return_data(vm);
  if (size == 0U) {
    return EVM_OK;
  }
  if (data == nullptr) {
    return EVM_ERR_INTERNAL;
  }

  uint8_t *copied = calloc(size, sizeof(uint8_t));
  if (copied == nullptr) {
    return EVM_ERR_OOM;
  }
  memcpy(copied, data, size);
  vm->return_data = copied;
  vm->return_data_size = size;
  return EVM_OK;
}

EVM_Status copy_return_data_to_memory(EVM_State *vm, size_t offset,
                                             size_t size) {
  if (size == 0U) {
    return EVM_OK;
  }

  EVM_Status status = ensure_memory_range(vm, offset, size);
  if (status != EVM_OK) {
    return status;
  }

  if (vm->return_data == nullptr || vm->return_data_size == 0U) {
    return EVM_OK;
  }

  size_t copied = vm->return_data_size;
  if (copied > size) {
    copied = size;
  }
  memcpy(vm->memory + offset, vm->return_data, copied);
  return EVM_OK;
}

bool size_to_u64(size_t value, uint64_t *out) {
#if SIZE_MAX > UINT64_MAX
  if (value > UINT64_MAX) {
    return false;
  }
#endif
  *out = (uint64_t)value;
  return true;
}

bool is_precompile_address(const uint256_t *address, uint8_t *out_id) {
  if (!uint256_fits_u64(address)) {
    return false;
  }
  uint64_t id = address->limbs[0];
  if (id < 1U || id > 9U) {
    return false;
  }
  *out_id = (uint8_t)id;
  return true;
}

uint32_t load_be_u32(const uint8_t *in) {
  return ((uint32_t)in[0] << 24U) | ((uint32_t)in[1] << 16U) |
         ((uint32_t)in[2] << 8U) | (uint32_t)in[3];
}

void sha256_hash(const uint8_t *data, size_t data_size,
                        uint8_t out[32]) {
  static constexpr size_t SHA256_DIGEST_BYTES = 32U;
  static constexpr uint8_t EMPTY_INPUT = 0U;

  const uint8_t *digest_input = data;
  if (digest_input == nullptr) {
    if (data_size != 0U) {
      memset(out, 0, SHA256_DIGEST_BYTES);
      return;
    }
    digest_input = &EMPTY_INPUT;
  }

  unsigned int digest_size = 0U;
  if (EVP_Digest(digest_input, data_size, out, &digest_size, EVP_sha256(),
                 nullptr) != 1 ||
      digest_size != SHA256_DIGEST_BYTES) {
    memset(out, 0, SHA256_DIGEST_BYTES);
  }
}

void ripemd160_hash(const uint8_t *data, size_t data_size,
                           uint8_t out[20]) {
  static constexpr size_t RIPEMD160_DIGEST_BYTES = 20U;
  static constexpr uint8_t EMPTY_INPUT = 0U;

  const uint8_t *digest_input = data;
  if (digest_input == nullptr) {
    if (data_size != 0U) {
      memset(out, 0, RIPEMD160_DIGEST_BYTES);
      return;
    }
    digest_input = &EMPTY_INPUT;
  }

  unsigned int digest_size = 0U;
  if (EVP_Digest(digest_input, data_size, out, &digest_size, EVP_ripemd160(),
                 nullptr) != 1 ||
      digest_size != RIPEMD160_DIGEST_BYTES) {
    memset(out, 0, RIPEMD160_DIGEST_BYTES);
  }
}

bool precompile_try_charge_gas(EVM_State *vm, uint64_t cost) {
  if (vm->gas_remaining < cost) {
    vm->gas_remaining = 0;
    return false;
  }
  vm->gas_remaining -= cost;
  return true;
}

EVM_Status set_zero_return_data_bytes(EVM_State *vm, size_t size) {
  if (size == 0U) {
    return set_return_data_bytes(vm, nullptr, 0U);
  }

  uint8_t *zeros = calloc(size, sizeof(uint8_t));
  if (zeros == nullptr) {
    return EVM_ERR_OOM;
  }
  EVM_Status status = set_return_data_bytes(vm, zeros, size);
  free(zeros);
  return status;
}
