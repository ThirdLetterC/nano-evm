const std = @import("std");

const release_cflags = &.{
    "-std=c23",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Werror",
    "-Wformat",
    "-Wformat-security",
    "-fstack-protector-strong",
    "-fPIE",
    "-D_FORTIFY_SOURCE=3",
    "-DNANO_EVM_DISABLE_CPU_DISPATCH=1",
    "-O2",
};

const debug_cflags = &.{
    "-std=c23",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Werror",
    "-Wformat",
    "-Wformat-security",
    "-fstack-protector-strong",
    "-fPIE",
    "-DNANO_EVM_DISABLE_CPU_DISPATCH=1",
    "-O0",
    "-g3",
};

const app_sources = &.{
    "src/main.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/contracts.c",
    "src/nanosol.c",
};

const solc_sources = &.{
    "src/nanosol_main.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/nanosol.c",
};

const node_sources = &.{
    "src/nano_node.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/nanosol.c",
};

const test_sources = &.{
    "tests/test_suite.c",
    "tests/test_helpers.c",
    "tests/test_arithmetic_and_stack.c",
    "tests/test_sub_underflow_wraps.c",
    "tests/test_div_by_zero_returns_zero.c",
    "tests/test_core_arithmetic_logic_opcodes.c",
    "tests/test_memory_ops.c",
    "tests/test_sha3_opcode.c",
    "tests/test_storage_ops.c",
    "tests/test_return_and_revert.c",
    "tests/test_sstore_refund_semantics.c",
    "tests/test_log_ops.c",
    "tests/test_contract_io_opcodes.c",
    "tests/test_high_value_low_complexity_opcodes.c",
    "tests/test_new_signed_and_transient_opcodes.c",
    "tests/test_new_context_external_and_copy_opcodes.c",
    "tests/test_new_call_create_and_selfdestruct_opcodes.c",
    "tests/test_precompile_dispatch.c",
    "tests/test_create2_increments_sender_nonce_for_create_addressing.c",
    "tests/test_call_frame_state_persistence.c",
    "tests/test_call_value_stipend_does_not_mint_gas.c",
    "tests/test_call_new_account_charge_for_empty_runtime_entry.c",
    "tests/test_modexp_adjusted_exponent_gas.c",
    "tests/test_out_of_gas.c",
    "tests/test_invalid_opcode_and_bytecode.c",
    "tests/test_memory_expansion_helper_cost.c",
    "tests/test_memory_expansion_overflow_is_runtime_error.c",
    "tests/test_bn254_pairing_api_input_validation.c",
    "tests/test_per_opcode_gas.c",
    "tests/test_api_and_error_surfaces.c",
    "tests/test_uint256_and_stack_helpers.c",
    "tests/test_stack_and_static_context_errors.c",
    "tests/test_execution_internal_and_depth_guards.c",
    "tests/test_hex_parser.c",
    "tests/test_contracts_module.c",
    "tests/test_nanosol_compiler_arithmetic_return.c",
    "tests/test_nanosol_compiler_control_flow_and_storage.c",
    "tests/test_nanosol_compiler_semantic_error.c",
    "tests/test_nanosol_compiler_numeric_literal_validation.c",
    "tests/test_nanosol_compiler_unterminated_block_comment.c",
    "tests/test_nanosol_cli_e2e.c",
    "tests/test_nano_node_state_file_validation.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/contracts.c",
    "src/nanosol.c",
};

const example_sources = &.{
    "src/contracts_examples.c",
    "src/evm.c",
    "src/evm/bn254_pairing.c",
    "src/stack.c",
    "src/uint256.c",
    "src/keccak.c",
    "src/contracts.c",
    "src/nanosol.c",
};

fn add_c_executable(
    b: *std.Build,
    name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    sanitize_c: ?std.zig.SanitizeC,
    sources: []const []const u8,
    cflags: []const []const u8,
) *std.Build.Step.Compile {
    const module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = sanitize_c,
    });
    module.addIncludePath(b.path("include"));
    module.addCSourceFiles(.{
        .files = sources,
        .flags = cflags,
    });

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = module,
    });
    add_hardening_linker_flags(exe, target);
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("secp256k1");
    exe.linkSystemLibrary("gmp");
    exe.linkSystemLibrary("b2");
    return exe;
}

fn add_hardening_linker_flags(
    exe: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
) void {
    _ = target;
    exe.pie = true;
    exe.link_z_relro = true;
    exe.link_z_lazy = false;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const nano_evm = add_c_executable(
        b,
        "nano-evm",
        target,
        .Debug,
        null,
        app_sources,
        release_cflags,
    );
    b.installArtifact(nano_evm);

    const nano_solc = add_c_executable(
        b,
        "nano-solc",
        target,
        .Debug,
        null,
        solc_sources,
        release_cflags,
    );
    const install_solc = b.addInstallArtifact(nano_solc, .{});
    const solc_step = b.step("solc", "Build nano-solc");
    solc_step.dependOn(&install_solc.step);

    const nano_node = add_c_executable(
        b,
        "nano-node",
        target,
        .Debug,
        null,
        node_sources,
        release_cflags,
    );
    const install_node = b.addInstallArtifact(nano_node, .{});
    const node_step = b.step("node", "Build nano-node");
    node_step.dependOn(&install_node.step);

    const test_suite = add_c_executable(
        b,
        "test_suite",
        target,
        .Debug,
        null,
        test_sources,
        release_cflags,
    );
    const run_test_suite = b.addRunArtifact(test_suite);
    run_test_suite.step.dependOn(&install_solc.step);
    run_test_suite.setEnvironmentVariable(
        "NANO_SOLC_PATH",
        b.getInstallPath(.bin, "nano-solc"),
    );
    run_test_suite.setEnvironmentVariable(
        "NANO_NODE_PATH",
        b.getInstallPath(.bin, "nano-node"),
    );
    run_test_suite.step.dependOn(&install_node.step);
    if (b.args) |args| {
        run_test_suite.addArgs(args);
    }
    const test_step = b.step("test", "Build and run test suite");
    test_step.dependOn(&run_test_suite.step);

    const contract_examples = add_c_executable(
        b,
        "contract_examples",
        target,
        .Debug,
        null,
        example_sources,
        release_cflags,
    );
    const run_contract_examples = b.addRunArtifact(contract_examples);
    if (b.args) |args| {
        run_contract_examples.addArgs(args);
    }
    const examples_step = b.step("examples", "Build and run contract examples");
    examples_step.dependOn(&run_contract_examples.step);

    const nano_evm_release = add_c_executable(
        b,
        "nano-evm-release",
        target,
        .ReleaseFast,
        null,
        app_sources,
        release_cflags,
    );
    const install_release = b.addInstallArtifact(nano_evm_release, .{});
    const release_step = b.step("release", "Build nano-evm-release in release mode");
    release_step.dependOn(&install_release.step);

    const nano_evm_debug = add_c_executable(
        b,
        "nano-evm-debug",
        target,
        .Debug,
        .full,
        app_sources,
        debug_cflags,
    );
    const install_debug = b.addInstallArtifact(nano_evm_debug, .{});
    const debug_step = b.step("debug", "Build nano-evm-debug with sanitizers");
    debug_step.dependOn(&install_debug.step);

    const test_suite_debug = add_c_executable(
        b,
        "test_suite-debug",
        target,
        .Debug,
        .full,
        test_sources,
        debug_cflags,
    );
    const run_test_suite_debug = b.addRunArtifact(test_suite_debug);
    if (b.args) |args| {
        run_test_suite_debug.addArgs(args);
    }
    const test_debug_step = b.step("test-debug", "Build and run debug test suite");
    test_debug_step.dependOn(&run_test_suite_debug.step);
}
