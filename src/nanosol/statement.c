#include "nanosol/common_internal.h"
#include "nanosol/statement_internal.h"

static const NanoSol_BuiltinSpec STATEMENT_BUILTINS[] = {
    {"sstore", 2, OPCODE_SSTORE, true},
    {"tstore", 2, OPCODE_TSTORE, true},
    {"mstore", 2, OPCODE_MSTORE, true},
    {"mstore8", 2, OPCODE_MSTORE8, true},
    {"return_mem", 2, OPCODE_RETURN, true},
    {"revert_mem", 2, OPCODE_REVERT, true},
    {"calldatacopy", 3, OPCODE_CALLDATACOPY, true},
    {"codecopy", 3, OPCODE_CODECOPY, true},
    {"returndatacopy", 3, OPCODE_RETURNDATACOPY, true},
    {"mcopy", 3, OPCODE_MCOPY, true},
    {"selfdestruct", 1, OPCODE_SELFDESTRUCT, false},
    {"pop", 1, OPCODE_POP, false},
};

static const NanoSol_BuiltinSpec *
compiler_find_statement_builtin(const NanoSol_Compiler *compiler,
                                const NanoSol_Token *name) {
  for (size_t i = 0;
       i < sizeof(STATEMENT_BUILTINS) / sizeof(STATEMENT_BUILTINS[0]); ++i) {
    if (compiler_identifier_equals(compiler, name,
                                   STATEMENT_BUILTINS[i].name)) {
      return &STATEMENT_BUILTINS[i];
    }
  }
  return nullptr;
}

static bool compiler_parse_statement_or_block(NanoSol_Compiler *compiler) {
  if (compiler->current.kind == TOKEN_LBRACE) {
    return compiler_parse_block(compiler);
  }

  if (compiler->scope_depth == SIZE_MAX) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "scope depth overflow");
    return false;
  }

  size_t parent_scope_depth = compiler->scope_depth;
  // Single statements get an implicit child scope for locals.
  compiler->scope_depth += 1U;
  bool parsed = compiler_parse_statement(compiler);
  compiler_pop_locals_to_scope_depth(compiler, parent_scope_depth);
  compiler->scope_depth = parent_scope_depth;
  return parsed;
}

static bool compiler_parse_statement_call(NanoSol_Compiler *compiler,
                                          const NanoSol_Token *name) {
  const NanoSol_BuiltinSpec *builtin =
      compiler_find_statement_builtin(compiler, name);
  if (builtin != nullptr) {
    size_t argument_count = 0;
    if (!compiler_parse_call_arguments(compiler, &argument_count)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_SEMICOLON,
                         "expected ';' after statement")) {
      return false;
    }
    if (argument_count != builtin->arity) {
      compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, name,
                         "builtin expects %zu argument(s), got %zu",
                         builtin->arity, argument_count);
      return false;
    }
    // Builtins that mirror raw opcodes may need operand reordering.
    if (builtin->reverse_arguments &&
        !compiler_emit_reverse_argument_order(compiler, argument_count)) {
      return false;
    }
    return compiler_emit_opcode(compiler, builtin->opcode);
  }

  ptrdiff_t function_index = compiler_find_function(compiler, name);
  if (function_index >= 0) {
    size_t argument_count = 0;
    if (!compiler_parse_call_arguments(compiler, &argument_count)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_SEMICOLON,
                         "expected ';' after statement")) {
      return false;
    }
    return compiler_emit_user_function_call(
        compiler, name, (size_t)function_index, argument_count, true);
  }

  compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, name,
                     "unknown statement function");
  return false;
}

bool compiler_parse_statement(NanoSol_Compiler *compiler) {
  if (compiler->current.kind == TOKEN_INVALID) {
    compiler_set_error(compiler, NANOSOL_ERR_LEX, &compiler->current, "%s",
                       token_invalid_message(&compiler->current));
    return false;
  }

  if (compiler_match(compiler, TOKEN_KW_LET) ||
      compiler_match(compiler, TOKEN_KW_UINT)) {
    NanoSol_Token name = compiler->current;
    if (!compiler_expect(compiler, TOKEN_IDENTIFIER,
                         "expected variable name")) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_ASSIGN,
                         "expected '=' in declaration")) {
      return false;
    }
    if (!compiler_parse_expression(compiler)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_SEMICOLON,
                         "expected ';' after declaration")) {
      return false;
    }
    if (!compiler_add_local(compiler, &name)) {
      return false;
    }
    // Slot is assigned at declaration-time; store the computed initializer.
    ptrdiff_t local_index = compiler_find_local(compiler, &name);
    if (local_index < 0) {
      compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &name,
                         "unknown variable");
      return false;
    }
    size_t offset = compiler->locals[(size_t)local_index].slot_offset;
    return compiler_emit_store_current_frame_slot(compiler, offset);
  }

  if (compiler_match(compiler, TOKEN_KW_RETURN)) {
    if (!compiler_parse_expression(compiler)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_SEMICOLON,
                         "expected ';' after return")) {
      return false;
    }
    if (compiler->current_function < compiler->functions_count) {
      return compiler_emit_internal_function_return(compiler);
    }
    return compiler_emit_external_word_return(compiler);
  }

  if (compiler_match(compiler, TOKEN_KW_IF)) {
    if (!compiler_expect(compiler, TOKEN_LPAREN, "expected '(' after if")) {
      return false;
    }
    if (!compiler_parse_expression(compiler)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_RPAREN,
                         "expected ')' after condition")) {
      return false;
    }

    size_t else_label = compiler_new_label(compiler);
    if (else_label == SIZE_MAX) {
      return false;
    }

    // Branch lowering: jump to else when condition is zero.
    if (!compiler_emit_opcode(compiler, OPCODE_ISZERO) ||
        !compiler_emit_jump(compiler, else_label, true)) {
      return false;
    }

    if (!compiler_parse_statement_or_block(compiler)) {
      return false;
    }

    if (compiler_match(compiler, TOKEN_KW_ELSE)) {
      size_t end_label = compiler_new_label(compiler);
      if (end_label == SIZE_MAX) {
        return false;
      }
      if (!compiler_emit_jump(compiler, end_label, false)) {
        return false;
      }
      if (!compiler_mark_label(compiler, else_label)) {
        return false;
      }
      if (!compiler_parse_statement_or_block(compiler)) {
        return false;
      }
      return compiler_mark_label(compiler, end_label);
    }

    return compiler_mark_label(compiler, else_label);
  }

  if (compiler_match(compiler, TOKEN_KW_WHILE)) {
    size_t loop_start = compiler_new_label(compiler);
    size_t loop_end = compiler_new_label(compiler);
    if (loop_start == SIZE_MAX || loop_end == SIZE_MAX) {
      return false;
    }

    // Canonical while lowering:
    // loop_start: eval condition -> jump loop_end on false -> body -> jump start.
    if (!compiler_mark_label(compiler, loop_start)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_LPAREN, "expected '(' after while")) {
      return false;
    }
    if (!compiler_parse_expression(compiler)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_RPAREN,
                         "expected ')' after condition")) {
      return false;
    }
    if (!compiler_emit_opcode(compiler, OPCODE_ISZERO) ||
        !compiler_emit_jump(compiler, loop_end, true)) {
      return false;
    }
    if (!compiler_parse_statement_or_block(compiler)) {
      return false;
    }
    if (!compiler_emit_jump(compiler, loop_start, false)) {
      return false;
    }
    return compiler_mark_label(compiler, loop_end);
  }

  if (compiler->current.kind == TOKEN_LBRACE) {
    return compiler_parse_block(compiler);
  }

  if (compiler->current.kind != TOKEN_IDENTIFIER) {
    compiler_set_error(compiler, NANOSOL_ERR_PARSE, &compiler->current,
                       "expected statement");
    return false;
  }

  NanoSol_Token name = compiler->current;
  compiler->current = lexer_next_token(&compiler->lexer);

  if (compiler_match(compiler, TOKEN_ASSIGN)) {
    ptrdiff_t local_index = compiler_find_local(compiler, &name);
    if (local_index < 0) {
      compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &name,
                         "unknown variable");
      return false;
    }

    if (!compiler_parse_expression(compiler)) {
      return false;
    }
    if (!compiler_expect(compiler, TOKEN_SEMICOLON,
                         "expected ';' after assignment")) {
      return false;
    }

    size_t offset = compiler->locals[(size_t)local_index].slot_offset;
    return compiler_emit_store_current_frame_slot(compiler, offset);
  }

  if (compiler_match(compiler, TOKEN_LPAREN)) {
    return compiler_parse_statement_call(compiler, &name);
  }

  compiler_set_error(compiler, NANOSOL_ERR_PARSE, &name,
                     "expected assignment or function call statement");
  return false;
}

bool compiler_parse_block(NanoSol_Compiler *compiler) {
  if (!compiler_expect(compiler, TOKEN_LBRACE, "expected '{'")) {
    return false;
  }

  if (compiler->scope_depth == SIZE_MAX) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "scope depth overflow");
    return false;
  }

  size_t parent_scope_depth = compiler->scope_depth;
  compiler->scope_depth += 1U;

  while (compiler->current.kind != TOKEN_RBRACE &&
         compiler->current.kind != TOKEN_EOF) {
    if (!compiler_parse_statement(compiler)) {
      compiler_pop_locals_to_scope_depth(compiler, parent_scope_depth);
      compiler->scope_depth = parent_scope_depth;
      return false;
    }
  }

  if (!compiler_expect(compiler, TOKEN_RBRACE, "expected '}'")) {
    compiler_pop_locals_to_scope_depth(compiler, parent_scope_depth);
    compiler->scope_depth = parent_scope_depth;
    return false;
  }

  compiler_pop_locals_to_scope_depth(compiler, parent_scope_depth);
  compiler->scope_depth = parent_scope_depth;
  return true;
}
