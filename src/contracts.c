#include "contracts.h"

#include <string.h>

static const EVM_ContractSpec BUILTIN_CONTRACTS[] = {
    {
        .name = "adder",
        .description = "Push 2 and 3, then ADD (stack top becomes 5).",
        .bytecode_hex = "6002600301",
        .suggested_gas_limit = 20,
    },
    {
        .name = "storage_roundtrip",
        .description = "SSTORE slot 0 with 1, then SLOAD slot 0.",
        .bytecode_hex = "6001600055600054",
        .suggested_gas_limit = 22'209,
    },
    {
        .name = "return_one_byte",
        .description = "Store 0xaa in memory and RETURN 1 byte.",
        .bytecode_hex = "60aa60005360016000f3",
        .suggested_gas_limit = 18,
    },
    {
        .name = "emit_log1",
        .description = "LOG1 with topic 0xaa and one-byte payload 0xff.",
        .bytecode_hex = "60ff60005360aa60016000a1",
        .suggested_gas_limit = 779,
    },
    {
        .name = "push0_increment",
        .description = "PUSH0, PUSH1 1, ADD (stack top becomes 1).",
        .bytecode_hex = "5f600101",
        .suggested_gas_limit = 8,
    },
    {
        .name = "dup_swap_add",
        .description = "Use DUP2, SWAP1, POP, then ADD (stack top becomes 4).",
        .bytecode_hex = "6002600381905001",
        .suggested_gas_limit = 17,
    },
    {
        .name = "jump_to_answer",
        .description = "JUMP to JUMPDEST and push 0x2a.",
        .bytecode_hex = "600456005b602a00",
        .suggested_gas_limit = 15,
    },
    {
        .name = "conditional_jump_true",
        .description = "JUMPI taken path to JUMPDEST and push 0x2a.",
        .bytecode_hex = "60016008576000005b602a00",
        .suggested_gas_limit = 20,
    },
    {
        .name = "pc_then_gas_pop",
        .description =
            "Push PC, push GAS, POP gas (stack top becomes initial PC=0).",
        .bytecode_hex = "585a5000",
        .suggested_gas_limit = 6,
    },
    {
        .name = "lt_true",
        .description = "LT demo: 2 < 3 (stack top becomes 1).",
        .bytecode_hex = "6002600310",
        .suggested_gas_limit = 9,
    },
    {
        .name = "gt_true",
        .description = "GT demo: 3 > 2 (stack top becomes 1).",
        .bytecode_hex = "6003600211",
        .suggested_gas_limit = 9,
    },
    {
        .name = "signed_compare",
        .description = "Signed comparisons with SLT/SGT (top becomes 1).",
        .bytecode_hex = "7fffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        "ffffffffffff600112"
                        "60017fffffffffffffffffffffffffffffffffffffffffffffffff"
                        "ffffffffffffffff13",
        .suggested_gas_limit = 18,
    },
    {
        .name = "eq_iszero_false",
        .description = "EQ then ISZERO on equal values (stack top becomes 0).",
        .bytecode_hex = "602a602a1415",
        .suggested_gas_limit = 12,
    },
    {
        .name = "bitwise_chain",
        .description = "AND/OR/XOR/NOT chain (stack top becomes ~0x16).",
        .bytecode_hex = "600f60331660401760551819",
        .suggested_gas_limit = 24,
    },
    {
        .name = "byte_extract",
        .description = "BYTE extracts 0x12 from 0x1234 at byte index 30.",
        .bytecode_hex = "601e6112341a",
        .suggested_gas_limit = 9,
    },
    {
        .name = "shift_roundtrip",
        .description = "SHL then SHR with SWAP1 (stack top returns to 1).",
        .bytecode_hex = "600860011b6008901c",
        .suggested_gas_limit = 18,
    },
    {
        .name = "sar_negative_one",
        .description = "Build -1 and SAR by 1 (stack top stays -1).",
        .bytecode_hex = "60015f6002031d",
        .suggested_gas_limit = 14,
    },
    {
        .name = "addmul_mod_mix",
        .description = "ADDMOD then MULMOD (top becomes 4).",
        .bytecode_hex = "6002600360050860046006600509",
        .suggested_gas_limit = 34,
    },
    {
        .name = "exp_signextend",
        .description =
            "EXP followed by SIGNEXTEND (top becomes sign-extended 0x80).",
        .bytecode_hex = "600260080a5f60800b",
        .suggested_gas_limit = 76,
    },
    {
        .name = "calldata_load_head",
        .description =
            "CALLDATALOAD at offset 0 (top becomes first calldata word).",
        .bytecode_hex = "5f35",
        .suggested_gas_limit = 16,
    },
    {
        .name = "calldata_size_only",
        .description = "CALLDATASIZE only (top becomes calldata length).",
        .bytecode_hex = "36",
        .suggested_gas_limit = 8,
    },
    {
        .name = "calldata_copy_return4",
        .description = "CALLDATACOPY 4 bytes to memory and RETURN them.",
        .bytecode_hex = "60045f5f3760045ff3",
        .suggested_gas_limit = 40,
    },
    {
        .name = "codecopy_return2",
        .description = "CODECOPY first 2 code bytes to memory and RETURN them.",
        .bytecode_hex = "60025f5f3960025ff3",
        .suggested_gas_limit = 40,
    },
    {
        .name = "codesize_returndata_probe",
        .description =
            "CODESIZE + RETURNDATASIZE, then zero-sized RETURNDATACOPY.",
        .bytecode_hex = "383d015f5f5f3e",
        .suggested_gas_limit = 30,
    },
    {
        .name = "sdiv_negative_two",
        .description = "Build -4 and divide by 2 with SDIV (top becomes -2).",
        .bytecode_hex = "5f600403600205",
        .suggested_gas_limit = 20,
    },
    {
        .name = "smod_negative_two",
        .description = "Build -5 and take SMOD 3 (top becomes -2).",
        .bytecode_hex = "5f600503600307",
        .suggested_gas_limit = 20,
    },
    {
        .name = "context_quad_add",
        .description = "Sum ADDRESS, ORIGIN, CALLER, CALLVALUE.",
        .bytecode_hex = "30320133013401",
        .suggested_gas_limit = 20,
    },
    {
        .name = "balance_plus_gasprice",
        .description =
            "BALANCE(0) + GASPRICE (top usually 0 in default VM context).",
        .bytecode_hex = "5f313a01",
        .suggested_gas_limit = 3'000,
    },
    {
        .name = "extcodecopy_return2_zero",
        .description =
            "EXTCODECOPY from unknown account and RETURN 2 zero bytes.",
        .bytecode_hex = "60025f5f60013c60025ff3",
        .suggested_gas_limit = 3'000,
    },
    {
        .name = "blockhash_zero",
        .description = "BLOCKHASH for default context (top becomes 0).",
        .bytecode_hex = "5f40",
        .suggested_gas_limit = 30,
    },
    {
        .name = "block_meta_sum",
        .description = "Sum COINBASE, TIMESTAMP, NUMBER, CHAINID.",
        .bytecode_hex = "41420143014601",
        .suggested_gas_limit = 40,
    },
    {
        .name = "transient_roundtrip",
        .description = "TSTORE key 1 with 0x2a, then TLOAD key 1.",
        .bytecode_hex = "602a60015d60015c",
        .suggested_gas_limit = 230,
    },
    {
        .name = "mcopy_return4",
        .description =
            "Write 0xaabb, MCOPY to duplicate it, RETURN first 4 bytes.",
        .bytecode_hex = "60aa60005360bb6001536002600060025e60046000f3",
        .suggested_gas_limit = 200,
    },
    {
        .name = "create2_staticcall_selfdestruct",
        .description = "Run CREATE2, STATICCALL, then SELFDESTRUCT to 0.",
        .bytecode_hex = "5f5f5f5ff55f5f5f5f5f5ffa5fff",
        .suggested_gas_limit = 40'000,
    },
    {
        .name = "keccak_storage_commit",
        .description =
            "Hash memory, commit hash to storage slot 1, and RETURN the hash.",
        .bytecode_hex = "602a600052602060002060015560015460005260206000f3",
        .suggested_gas_limit = 25'000,
    },
    {
        .name = "jump_table_arithmetic",
        .description =
            "Branch via JUMPI/JUMP and compute (5*6)+7 on the taken path.",
        .bytecode_hex = "6001600a5760006013565b60056006026007015b00",
        .suggested_gas_limit = 80,
    },
    {
        .name = "calldata_dispatch_default",
        .description = "If calldata empty, RETURN 0xdeadbeef; else echo first "
                       "4 calldata bytes.",
        .bytecode_hex =
            "3615600e5760045f5f3760045ff35b63deadbeef5f526004601cf3",
        .suggested_gas_limit = 120,
    },
    {
        .name = "log_topic_hash_return",
        .description =
            "LOG1 with SHA3(topic) over payload byte, then RETURN that hash.",
        .bytecode_hex = "60ab60005360016000208060016000a160005260206000f3",
        .suggested_gas_limit = 2'000,
    },
    {
        .name = "transient_persistent_sum",
        .description =
            "Store in TSTORE and SSTORE at key 1, then sum TLOAD+SLOAD.",
        .bytecode_hex = "602a60015d600760015560015c60015401",
        .suggested_gas_limit = 23'000,
    },
    {
        .name = "mcopy_overlap_return4",
        .description = "Build 4 bytes in memory, overlap MCOPY, then RETURN "
                       "first 4 bytes.",
        .bytecode_hex =
            "601160005360226001536033600253604460035360035f60015e60046000f3",
        .suggested_gas_limit = 300,
    },
    {
        .name = "codecopy_sha3_return",
        .description =
            "CODECOPY first 8 bytes, SHA3 them, then RETURN the 32-byte hash.",
        .bytecode_hex = "60085f5f39600860002060005260206000f3",
        .suggested_gas_limit = 200,
    },
    {
        .name = "external_probe_combo",
        .description = "Probe BALANCE/EXTCODESIZE/EXTCODEHASH for zero account "
                       "and ISZERO(sum).",
        .bytecode_hex = "5f315f3b015f3f0115",
        .suggested_gas_limit = 400,
    },
    {
        .name = "call_family_accumulate",
        .description =
            "Run CALL/CALLCODE/DELEGATECALL/STATICCALL and sum success flags.",
        .bytecode_hex = "5f5f5f5f5f5f5ff15f5f5f5f5f5f5ff25f5f5f5f5f5ff45f5f5f5f"
                        "5f5ffa01010100",
        .suggested_gas_limit = 3'200,
    },
    {
        .name = "create_create2_selfdestruct",
        .description =
            "Run CREATE and CREATE2, add results, then SELFDESTRUCT.",
        .bytecode_hex = "5f5f5ff05f5f5f5ff5015fff",
        .suggested_gas_limit = 70'000,
    },
};

const EVM_ContractSpec *contracts_list(size_t *out_count) {
  if (out_count != nullptr) {
    *out_count = sizeof(BUILTIN_CONTRACTS) / sizeof(BUILTIN_CONTRACTS[0]);
  }
  return BUILTIN_CONTRACTS;
}

const EVM_ContractSpec *contracts_find(const char *name) {
  if (name == nullptr) {
    return nullptr;
  }

  size_t contract_count = 0;
  const EVM_ContractSpec *contracts = contracts_list(&contract_count);
  for (size_t i = 0; i < contract_count; ++i) {
    if (strcmp(contracts[i].name, name) == 0) {
      return &contracts[i];
    }
  }
  return nullptr;
}

EVM_Status contracts_load_code(const EVM_ContractSpec *spec, uint8_t **out_code,
                               size_t *out_size) {
  if (spec == nullptr || spec->bytecode_hex == nullptr || out_code == nullptr ||
      out_size == nullptr) {
    return EVM_ERR_INVALID_BYTECODE;
  }
  return evm_load_hex(spec->bytecode_hex, out_code, out_size);
}
