#include "test_helpers.h"

void test_bn254_pairing_api_input_validation() {
  bool out_is_one = true;
  uint8_t one_byte = 0U;

  assert(!bn254_pairing_check(nullptr, 1U, &out_is_one));
  assert(!bn254_pairing_check(&one_byte, 1U, &out_is_one));
  assert(!bn254_pairing_check(&one_byte, 1U, nullptr));

  out_is_one = false;
  assert(bn254_pairing_check(nullptr, 0U, &out_is_one));
  assert(out_is_one);
}

