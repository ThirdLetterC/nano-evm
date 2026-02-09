#include "test_helpers.h"

void test_contracts_module() {
  size_t contract_count = 0;
  const EVM_ContractSpec *contracts = contracts_list(&contract_count);
  assert(contracts != nullptr);
  assert(contract_count >= 34);

  const EVM_ContractSpec *adder = contracts_find("adder");
  assert(adder != nullptr);
  assert(strcmp(adder->bytecode_hex, "6002600301") == 0);

  const EVM_ContractSpec *roundtrip = contracts_find("storage_roundtrip");
  assert(roundtrip != nullptr);

  const EVM_ContractSpec *return_one_byte = contracts_find("return_one_byte");
  assert(return_one_byte != nullptr);

  const EVM_ContractSpec *emit_log = contracts_find("emit_log1");
  assert(emit_log != nullptr);

  const EVM_ContractSpec *push0_increment = contracts_find("push0_increment");
  assert(push0_increment != nullptr);
  assert(strcmp(push0_increment->bytecode_hex, "5f600101") == 0);

  const EVM_ContractSpec *dup_swap_add = contracts_find("dup_swap_add");
  assert(dup_swap_add != nullptr);

  const EVM_ContractSpec *jump_to_answer = contracts_find("jump_to_answer");
  assert(jump_to_answer != nullptr);

  const EVM_ContractSpec *conditional_jump_true =
      contracts_find("conditional_jump_true");
  assert(conditional_jump_true != nullptr);

  const EVM_ContractSpec *pc_then_gas_pop = contracts_find("pc_then_gas_pop");
  assert(pc_then_gas_pop != nullptr);

  const EVM_ContractSpec *lt_true = contracts_find("lt_true");
  assert(lt_true != nullptr);
  assert(strcmp(lt_true->bytecode_hex, "6002600310") == 0);

  const EVM_ContractSpec *gt_true = contracts_find("gt_true");
  assert(gt_true != nullptr);

  const EVM_ContractSpec *signed_compare = contracts_find("signed_compare");
  assert(signed_compare != nullptr);

  const EVM_ContractSpec *eq_iszero_false = contracts_find("eq_iszero_false");
  assert(eq_iszero_false != nullptr);

  const EVM_ContractSpec *bitwise_chain = contracts_find("bitwise_chain");
  assert(bitwise_chain != nullptr);

  const EVM_ContractSpec *byte_extract = contracts_find("byte_extract");
  assert(byte_extract != nullptr);

  const EVM_ContractSpec *shift_roundtrip = contracts_find("shift_roundtrip");
  assert(shift_roundtrip != nullptr);

  const EVM_ContractSpec *sar_negative_one = contracts_find("sar_negative_one");
  assert(sar_negative_one != nullptr);

  const EVM_ContractSpec *addmul_mod_mix = contracts_find("addmul_mod_mix");
  assert(addmul_mod_mix != nullptr);

  const EVM_ContractSpec *exp_signextend = contracts_find("exp_signextend");
  assert(exp_signextend != nullptr);
  assert(strcmp(exp_signextend->bytecode_hex, "600260080a5f60800b") == 0);

  const EVM_ContractSpec *calldata_load_head =
      contracts_find("calldata_load_head");
  assert(calldata_load_head != nullptr);

  const EVM_ContractSpec *calldata_size_only =
      contracts_find("calldata_size_only");
  assert(calldata_size_only != nullptr);

  const EVM_ContractSpec *calldata_copy_return4 =
      contracts_find("calldata_copy_return4");
  assert(calldata_copy_return4 != nullptr);

  const EVM_ContractSpec *codecopy_return2 = contracts_find("codecopy_return2");
  assert(codecopy_return2 != nullptr);

  const EVM_ContractSpec *codesize_returndata_probe =
      contracts_find("codesize_returndata_probe");
  assert(codesize_returndata_probe != nullptr);

  const EVM_ContractSpec *sdiv_negative_two =
      contracts_find("sdiv_negative_two");
  assert(sdiv_negative_two != nullptr);

  const EVM_ContractSpec *smod_negative_two =
      contracts_find("smod_negative_two");
  assert(smod_negative_two != nullptr);

  const EVM_ContractSpec *context_quad_add = contracts_find("context_quad_add");
  assert(context_quad_add != nullptr);

  const EVM_ContractSpec *balance_plus_gasprice =
      contracts_find("balance_plus_gasprice");
  assert(balance_plus_gasprice != nullptr);

  const EVM_ContractSpec *extcodecopy_return2_zero =
      contracts_find("extcodecopy_return2_zero");
  assert(extcodecopy_return2_zero != nullptr);

  const EVM_ContractSpec *blockhash_zero = contracts_find("blockhash_zero");
  assert(blockhash_zero != nullptr);

  const EVM_ContractSpec *block_meta_sum = contracts_find("block_meta_sum");
  assert(block_meta_sum != nullptr);

  const EVM_ContractSpec *transient_roundtrip =
      contracts_find("transient_roundtrip");
  assert(transient_roundtrip != nullptr);

  const EVM_ContractSpec *mcopy_return4 = contracts_find("mcopy_return4");
  assert(mcopy_return4 != nullptr);

  const EVM_ContractSpec *create2_staticcall_selfdestruct =
      contracts_find("create2_staticcall_selfdestruct");
  assert(create2_staticcall_selfdestruct != nullptr);

  const EVM_ContractSpec *keccak_storage_commit =
      contracts_find("keccak_storage_commit");
  assert(keccak_storage_commit != nullptr);

  const EVM_ContractSpec *jump_table_arithmetic =
      contracts_find("jump_table_arithmetic");
  assert(jump_table_arithmetic != nullptr);

  const EVM_ContractSpec *calldata_dispatch_default =
      contracts_find("calldata_dispatch_default");
  assert(calldata_dispatch_default != nullptr);

  const EVM_ContractSpec *log_topic_hash_return =
      contracts_find("log_topic_hash_return");
  assert(log_topic_hash_return != nullptr);

  const EVM_ContractSpec *transient_persistent_sum =
      contracts_find("transient_persistent_sum");
  assert(transient_persistent_sum != nullptr);

  const EVM_ContractSpec *mcopy_overlap_return4 =
      contracts_find("mcopy_overlap_return4");
  assert(mcopy_overlap_return4 != nullptr);

  const EVM_ContractSpec *codecopy_sha3_return =
      contracts_find("codecopy_sha3_return");
  assert(codecopy_sha3_return != nullptr);

  const EVM_ContractSpec *external_probe_combo =
      contracts_find("external_probe_combo");
  assert(external_probe_combo != nullptr);

  const EVM_ContractSpec *call_family_accumulate =
      contracts_find("call_family_accumulate");
  assert(call_family_accumulate != nullptr);

  const EVM_ContractSpec *create_create2_selfdestruct =
      contracts_find("create_create2_selfdestruct");
  assert(create_create2_selfdestruct != nullptr);

  assert(contracts_find("missing_contract") == nullptr);
  assert(contracts_find(nullptr) == nullptr);

  uint8_t *code = nullptr;
  size_t code_size = 0;
  static constexpr uint8_t io_call_data[4] = {0xde, 0xad, 0xbe, 0xef};
  EVM_Status status = contracts_load_code(adder, &code, &code_size);
  assert(status == EVM_OK);
  assert(code != nullptr);
  assert(code_size == 5);

  EVM_State vm;
  status = evm_init(&vm, code, code_size, adder->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 5);
  cleanup(&vm, code);

  status = contracts_load_code(push0_increment, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, push0_increment->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = contracts_load_code(dup_swap_add, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, dup_swap_add->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 4);
  cleanup(&vm, code);

  status = contracts_load_code(jump_to_answer, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, jump_to_answer->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x2a);
  cleanup(&vm, code);

  status = contracts_load_code(conditional_jump_true, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size,
                    conditional_jump_true->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x2a);
  cleanup(&vm, code);

  status = contracts_load_code(pc_then_gas_pop, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, pc_then_gas_pop->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = contracts_load_code(lt_true, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, lt_true->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = contracts_load_code(gt_true, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, gt_true->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = contracts_load_code(signed_compare, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, signed_compare->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = contracts_load_code(eq_iszero_false, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, eq_iszero_false->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = contracts_load_code(bitwise_chain, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, bitwise_chain->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  uint8_t not_e9[32];
  memset(not_e9, 0xff, sizeof(not_e9));
  not_e9[31] = 0xe9;
  assert_top_bytes32(&vm, not_e9);
  cleanup(&vm, code);

  status = contracts_load_code(byte_extract, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, byte_extract->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0x12);
  cleanup(&vm, code);

  status = contracts_load_code(shift_roundtrip, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, shift_roundtrip->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 1);
  cleanup(&vm, code);

  status = contracts_load_code(sar_negative_one, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, sar_negative_one->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  uint8_t all_ff[32];
  memset(all_ff, 0xff, sizeof(all_ff));
  assert_top_bytes32(&vm, all_ff);
  cleanup(&vm, code);

  status = contracts_load_code(addmul_mod_mix, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, addmul_mod_mix->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 4);
  cleanup(&vm, code);

  status = contracts_load_code(exp_signextend, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, exp_signextend->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  uint8_t signextend_expected[32];
  memset(signextend_expected, 0xff, sizeof(signextend_expected));
  signextend_expected[31] = 0x80;
  assert_top_bytes32(&vm, signextend_expected);
  cleanup(&vm, code);

  status = contracts_load_code(calldata_load_head, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, calldata_load_head->suggested_gas_limit);
  assert(status == EVM_OK);
  vm.call_data = io_call_data;
  vm.call_data_size = sizeof(io_call_data);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  uint8_t calldata_load_expected[32] = {0};
  calldata_load_expected[0] = 0xde;
  calldata_load_expected[1] = 0xad;
  calldata_load_expected[2] = 0xbe;
  calldata_load_expected[3] = 0xef;
  assert_top_bytes32(&vm, calldata_load_expected);
  cleanup(&vm, code);

  status = contracts_load_code(calldata_size_only, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, calldata_size_only->suggested_gas_limit);
  assert(status == EVM_OK);
  vm.call_data = io_call_data;
  vm.call_data_size = sizeof(io_call_data);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, sizeof(io_call_data));
  cleanup(&vm, code);

  status = contracts_load_code(calldata_copy_return4, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size,
                    calldata_copy_return4->suggested_gas_limit);
  assert(status == EVM_OK);
  vm.call_data = io_call_data;
  vm.call_data_size = sizeof(io_call_data);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(vm.return_data_size == 4);
  assert(vm.return_data != nullptr);
  assert(memcmp(vm.return_data, io_call_data, 4) == 0);
  cleanup(&vm, code);

  status = contracts_load_code(codecopy_return2, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, codecopy_return2->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(vm.return_data_size == 2);
  assert(vm.return_data != nullptr);
  assert(vm.return_data[0] == 0x60);
  assert(vm.return_data[1] == 0x02);
  cleanup(&vm, code);

  status = contracts_load_code(codesize_returndata_probe, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size,
                    codesize_returndata_probe->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 7);
  cleanup(&vm, code);

  status = contracts_load_code(sdiv_negative_two, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, sdiv_negative_two->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  uint8_t minus_two[32];
  memset(minus_two, 0xff, sizeof(minus_two));
  minus_two[31] = 0xfe;
  assert_top_bytes32(&vm, minus_two);
  cleanup(&vm, code);

  status = contracts_load_code(smod_negative_two, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, smod_negative_two->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_bytes32(&vm, minus_two);
  cleanup(&vm, code);

  status = contracts_load_code(context_quad_add, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, context_quad_add->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = contracts_load_code(balance_plus_gasprice, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size,
                    balance_plus_gasprice->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = contracts_load_code(extcodecopy_return2_zero, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size,
                    extcodecopy_return2_zero->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(vm.return_data_size == 2);
  assert(vm.return_data != nullptr);
  assert(vm.return_data[0] == 0x00);
  assert(vm.return_data[1] == 0x00);
  cleanup(&vm, code);

  status = contracts_load_code(blockhash_zero, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, blockhash_zero->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = contracts_load_code(block_meta_sum, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, block_meta_sum->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert_top_u64(&vm, 0);
  cleanup(&vm, code);

  status = contracts_load_code(transient_roundtrip, &code, &code_size);
  assert(status == EVM_OK);
  status =
      evm_init(&vm, code, code_size, transient_roundtrip->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  status = contracts_load_code(mcopy_return4, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size, mcopy_return4->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_ERR_INVALID_OPCODE);
  cleanup(&vm, code);

  status =
      contracts_load_code(create2_staticcall_selfdestruct, &code, &code_size);
  assert(status == EVM_OK);
  status = evm_init(&vm, code, code_size,
                    create2_staticcall_selfdestruct->suggested_gas_limit);
  assert(status == EVM_OK);
  status = evm_execute(&vm);
  assert(status == EVM_OK);
  assert(stack_depth(&vm.stack) == 2);
  cleanup(&vm, code);
}
