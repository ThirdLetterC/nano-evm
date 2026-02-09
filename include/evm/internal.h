#ifndef EVM_INTERNAL_H
#define EVM_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

static constexpr uint64_t GAS_ZERO = 0;
static constexpr uint64_t GAS_BASE = 2;
static constexpr uint64_t GAS_VERYLOW = 3;
static constexpr uint64_t GAS_LOW = 5;
static constexpr uint64_t GAS_MID = 8;
static constexpr uint64_t GAS_HIGH = 10;
static constexpr uint64_t GAS_JUMPDEST = 1;
static constexpr uint64_t GAS_SHA3 = 30;
static constexpr uint64_t GAS_SHA3_WORD = 6;
static constexpr uint64_t GAS_SLOAD_WARM = 100;
static constexpr uint64_t GAS_SLOAD_COLD = 2'100;
static constexpr uint64_t GAS_SSTORE_SET = 20'000;
static constexpr uint64_t GAS_SSTORE_RESET = 2'900;
static constexpr uint64_t GAS_SSTORE_CLEARS_SCHEDULE = 4'800;
static constexpr uint64_t GAS_LOG = 375;
static constexpr uint64_t GAS_LOG_TOPIC = 375;
static constexpr uint64_t GAS_LOG_DATA = 8;
static constexpr uint64_t GAS_EXP_BYTE = 50;
static constexpr uint64_t GAS_COPY_WORD = 3;
static constexpr uint64_t GAS_INITCODE_WORD = 2;
static constexpr uint64_t GAS_BLOCKHASH = 20;
static constexpr uint64_t GAS_EXTERNAL = 100;
static constexpr uint64_t GAS_ACCOUNT_ACCESS_COLD = 2'600;
static constexpr uint64_t GAS_ACCOUNT_ACCESS_COLD_SURCHARGE =
    GAS_ACCOUNT_ACCESS_COLD - GAS_EXTERNAL;
static constexpr uint64_t GAS_TLOAD = 100;
static constexpr uint64_t GAS_TSTORE = 100;
static constexpr uint64_t GAS_CALL = GAS_EXTERNAL;
static constexpr uint64_t GAS_CALL_VALUE_TRANSFER = 9'000;
static constexpr uint64_t GAS_CALL_NEW_ACCOUNT = 25'000;
static constexpr uint64_t GAS_CALL_STIPEND = 2'300;
static constexpr uint64_t GAS_CREATE = 32'000;
static constexpr uint64_t GAS_CODE_DEPOSIT = 200;
static constexpr size_t MAX_CODE_SIZE = 24'576;
static constexpr size_t MAX_INITCODE_SIZE = 49'152;
static constexpr uint64_t GAS_SELFDESTRUCT = 5'000;
static constexpr uint64_t GAS_PRECOMPILE_ECRECOVER = 3'000;
static constexpr uint64_t GAS_PRECOMPILE_SHA256_BASE = 60;
static constexpr uint64_t GAS_PRECOMPILE_SHA256_WORD = 12;
static constexpr uint64_t GAS_PRECOMPILE_RIPEMD160_BASE = 600;
static constexpr uint64_t GAS_PRECOMPILE_RIPEMD160_WORD = 120;
static constexpr uint64_t GAS_PRECOMPILE_IDENTITY_BASE = 15;
static constexpr uint64_t GAS_PRECOMPILE_IDENTITY_WORD = 3;
static constexpr uint64_t GAS_PRECOMPILE_MODEXP_MIN = 200;
static constexpr uint64_t GAS_PRECOMPILE_BN256ADD = 150;
static constexpr uint64_t GAS_PRECOMPILE_BN256MUL = 6'000;
static constexpr uint64_t GAS_PRECOMPILE_BN256PAIRING_BASE = 45'000;
static constexpr uint64_t GAS_PRECOMPILE_BN256PAIRING_PER_PAIR = 34'000;
static constexpr size_t EVM_MAX_CALL_DEPTH = 1'024;

#endif
