#include <stdio.h>

#include "test_cases.h"

int main() {
  test_arithmetic_and_stack();
  test_sub_underflow_wraps();
  test_div_by_zero_returns_zero();
  test_core_arithmetic_logic_opcodes();
  test_memory_ops();
  test_sha3_opcode();
  test_storage_ops();
  test_return_and_revert();
  test_sstore_refund_semantics();
  test_log_ops();
  test_contract_io_opcodes();
  test_high_value_low_complexity_opcodes();
  test_new_signed_and_transient_opcodes();
  test_new_context_external_and_copy_opcodes();
  test_new_call_create_and_selfdestruct_opcodes();
  test_precompile_dispatch();
  test_create2_increments_sender_nonce_for_create_addressing();
  test_call_frame_state_persistence();
  test_call_value_stipend_does_not_mint_gas();
  test_call_new_account_charge_for_empty_runtime_entry();
  test_modexp_adjusted_exponent_gas();
  test_out_of_gas();
  test_invalid_opcode_and_bytecode();
  test_memory_expansion_helper_cost();
  test_memory_expansion_overflow_is_runtime_error();
  test_bn254_pairing_api_input_validation();
  test_per_opcode_gas();
  test_api_and_error_surfaces();
  test_uint256_and_stack_helpers();
  test_stack_and_static_context_errors();
  test_execution_internal_and_depth_guards();
  test_hex_parser();
  test_contracts_module();
  test_nanosol_compiler_arithmetic_return();
  test_nanosol_compiler_control_flow_and_storage();
  test_nanosol_compiler_semantic_error();
  test_nanosol_compiler_numeric_literal_validation();
  test_nanosol_compiler_unterminated_block_comment();
  test_nanosol_cli_e2e_compile_success();
  test_nanosol_cli_e2e_run_success();
  test_nanosol_cli_e2e_compile_failure();
  test_nano_node_rejects_oversized_code_state();
  test_nano_node_rejects_runtime_account_invalid_flags();
  test_state_clone_overflow_guards();

  puts("All tests passed.");
  return 0;
}
