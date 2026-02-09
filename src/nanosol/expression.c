#include "nanosol/common_internal.h"
#include "nanosol/expression_internal.h"

static bool compiler_parse_primary(NanoSol_Compiler *compiler) {
  NanoSol_Token token = compiler->current;
  if (token.kind == TOKEN_INVALID) {
    compiler_set_error(compiler, NANOSOL_ERR_LEX, &token, "%s",
                       token_invalid_message(&token));
    return false;
  }
  switch (token.kind) {
  case TOKEN_NUMBER:
    compiler->current = lexer_next_token(&compiler->lexer);
    return compiler_emit_push_numeric_literal(compiler, &token);
  case TOKEN_KW_TRUE:
    compiler->current = lexer_next_token(&compiler->lexer);
    return compiler_emit_push_u64(compiler, 1);
  case TOKEN_KW_FALSE:
    compiler->current = lexer_next_token(&compiler->lexer);
    return compiler_emit_push_u64(compiler, 0);
  case TOKEN_LPAREN:
    compiler->current = lexer_next_token(&compiler->lexer);
    if (!compiler_parse_expression(compiler)) {
      return false;
    }
    return compiler_expect(compiler, TOKEN_RPAREN,
                           "expected ')' after expression");
  case TOKEN_IDENTIFIER: {
    compiler->current = lexer_next_token(&compiler->lexer);
    if (compiler_match(compiler, TOKEN_LPAREN)) {
      // Identifier followed by '(' is either a builtin opcode wrapper or a
      // user-defined function call.
      const NanoSol_BuiltinSpec *builtin =
          compiler_find_expression_builtin(compiler, &token);
      if (builtin != nullptr) {
        size_t argument_count = 0;
        if (!compiler_parse_call_arguments(compiler, &argument_count)) {
          return false;
        }
        if (argument_count != builtin->arity) {
          compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &token,
                             "builtin expects %zu argument(s), got %zu",
                             builtin->arity, argument_count);
          return false;
        }
        if (builtin->reverse_arguments &&
            !compiler_emit_reverse_argument_order(compiler, argument_count)) {
          return false;
        }
        return compiler_emit_opcode(compiler, builtin->opcode);
      }

      ptrdiff_t function_index = compiler_find_function(compiler, &token);
      if (function_index < 0) {
        compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &token,
                           "unknown function in expression");
        return false;
      }

      size_t argument_count = 0;
      if (!compiler_parse_call_arguments(compiler, &argument_count)) {
        return false;
      }
      return compiler_emit_user_function_call(
          compiler, &token, (size_t)function_index, argument_count, false);
    }

    ptrdiff_t local_index = compiler_find_local(compiler, &token);
    if (local_index < 0) {
      compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &token,
                         "unknown variable");
      return false;
    }
    size_t offset = compiler->locals[(size_t)local_index].slot_offset;
    return compiler_emit_load_current_frame_slot(compiler, offset);
  }
  default:
    compiler_set_error(compiler, NANOSOL_ERR_PARSE, &token,
                       "expected expression");
    return false;
  }
}

static bool compiler_parse_unary(NanoSol_Compiler *compiler) {
  if (compiler_match(compiler, TOKEN_BANG)) {
    return compiler_parse_unary(compiler) &&
           compiler_emit_opcode(compiler, OPCODE_ISZERO);
  }

  if (compiler_match(compiler, TOKEN_MINUS)) {
    if (!compiler_parse_unary(compiler)) {
      return false;
    }
    // Lower unary minus to (0 - value) using stack swaps.
    return compiler_emit_push_u64(compiler, 0) &&
           compiler_emit_opcode(compiler, OPCODE_SWAP1) &&
           compiler_emit_opcode(compiler, OPCODE_SUB);
  }

  return compiler_parse_primary(compiler);
}

static bool compiler_parse_multiplicative(NanoSol_Compiler *compiler) {
  if (!compiler_parse_unary(compiler)) {
    return false;
  }

  while (true) {
    NanoSol_TokenKind op = compiler->current.kind;
    if (op != TOKEN_STAR && op != TOKEN_SLASH && op != TOKEN_PERCENT) {
      break;
    }
    compiler->current = lexer_next_token(&compiler->lexer);
    if (!compiler_parse_unary(compiler)) {
      return false;
    }
    uint8_t opcode = (op == TOKEN_STAR)    ? OPCODE_MUL
                     : (op == TOKEN_SLASH) ? OPCODE_DIV
                                           : OPCODE_MOD;
    if (!compiler_emit_opcode(compiler, opcode)) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_additive(NanoSol_Compiler *compiler) {
  if (!compiler_parse_multiplicative(compiler)) {
    return false;
  }
  while (true) {
    NanoSol_TokenKind op = compiler->current.kind;
    if (op != TOKEN_PLUS && op != TOKEN_MINUS) {
      break;
    }
    compiler->current = lexer_next_token(&compiler->lexer);
    if (!compiler_parse_multiplicative(compiler)) {
      return false;
    }
    if (!compiler_emit_opcode(compiler,
                              (op == TOKEN_PLUS) ? OPCODE_ADD : OPCODE_SUB)) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_shift(NanoSol_Compiler *compiler) {
  if (!compiler_parse_additive(compiler)) {
    return false;
  }
  while (true) {
    NanoSol_TokenKind op = compiler->current.kind;
    if (op != TOKEN_SHL && op != TOKEN_SHR) {
      break;
    }
    compiler->current = lexer_next_token(&compiler->lexer);
    if (!compiler_parse_additive(compiler)) {
      return false;
    }
    if (!compiler_emit_opcode(compiler,
                              (op == TOKEN_SHL) ? OPCODE_SHL : OPCODE_SHR)) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_relational(NanoSol_Compiler *compiler) {
  if (!compiler_parse_shift(compiler)) {
    return false;
  }
  while (true) {
    NanoSol_TokenKind op = compiler->current.kind;
    if (op != TOKEN_LT && op != TOKEN_GT && op != TOKEN_LE && op != TOKEN_GE) {
      break;
    }
    compiler->current = lexer_next_token(&compiler->lexer);
    if (!compiler_parse_shift(compiler)) {
      return false;
    }

    if (op == TOKEN_LT && !compiler_emit_opcode(compiler, OPCODE_LT)) {
      return false;
    }
    if (op == TOKEN_GT && !compiler_emit_opcode(compiler, OPCODE_GT)) {
      return false;
    }
    // EVM has no dedicated <=/>= opcodes, so invert >/< respectively.
    if (op == TOKEN_LE && (!compiler_emit_opcode(compiler, OPCODE_GT) ||
                           !compiler_emit_opcode(compiler, OPCODE_ISZERO))) {
      return false;
    }
    if (op == TOKEN_GE && (!compiler_emit_opcode(compiler, OPCODE_LT) ||
                           !compiler_emit_opcode(compiler, OPCODE_ISZERO))) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_equality(NanoSol_Compiler *compiler) {
  if (!compiler_parse_relational(compiler)) {
    return false;
  }
  while (true) {
    NanoSol_TokenKind op = compiler->current.kind;
    if (op != TOKEN_EQEQ && op != TOKEN_NEQ) {
      break;
    }
    compiler->current = lexer_next_token(&compiler->lexer);
    if (!compiler_parse_relational(compiler)) {
      return false;
    }

    if (!compiler_emit_opcode(compiler, OPCODE_EQ)) {
      return false;
    }
    if (op == TOKEN_NEQ && !compiler_emit_opcode(compiler, OPCODE_ISZERO)) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_bitwise_and(NanoSol_Compiler *compiler) {
  if (!compiler_parse_equality(compiler)) {
    return false;
  }
  while (compiler_match(compiler, TOKEN_BITAND)) {
    if (!compiler_parse_equality(compiler)) {
      return false;
    }
    if (!compiler_emit_opcode(compiler, OPCODE_AND)) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_bitwise_xor(NanoSol_Compiler *compiler) {
  if (!compiler_parse_bitwise_and(compiler)) {
    return false;
  }
  while (compiler_match(compiler, TOKEN_BITXOR)) {
    if (!compiler_parse_bitwise_and(compiler)) {
      return false;
    }
    if (!compiler_emit_opcode(compiler, OPCODE_XOR)) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_bitwise_or(NanoSol_Compiler *compiler) {
  if (!compiler_parse_bitwise_xor(compiler)) {
    return false;
  }
  while (compiler_match(compiler, TOKEN_BITOR)) {
    if (!compiler_parse_bitwise_xor(compiler)) {
      return false;
    }
    if (!compiler_emit_opcode(compiler, OPCODE_OR)) {
      return false;
    }
  }
  return true;
}

static bool compiler_parse_logical_and(NanoSol_Compiler *compiler) {
  if (!compiler_parse_bitwise_or(compiler)) {
    return false;
  }
  while (compiler_match(compiler, TOKEN_ANDAND)) {
    size_t false_label = compiler_new_label(compiler);
    size_t end_label = compiler_new_label(compiler);
    if (false_label == SIZE_MAX || end_label == SIZE_MAX) {
      return false;
    }

    // Short-circuit: if lhs is false, keep it and skip rhs evaluation.
    if (!compiler_emit_booleanize_top(compiler) ||
        !compiler_emit_opcode(compiler, OPCODE_DUP1) ||
        !compiler_emit_opcode(compiler, OPCODE_ISZERO) ||
        !compiler_emit_jump(compiler, false_label, true) ||
        !compiler_emit_opcode(compiler, OPCODE_POP)) {
      return false;
    }

    if (!compiler_parse_bitwise_or(compiler) ||
        !compiler_emit_booleanize_top(compiler) ||
        !compiler_emit_jump(compiler, end_label, false) ||
        !compiler_mark_label(compiler, false_label) ||
        !compiler_mark_label(compiler, end_label)) {
      return false;
    }
  }
  return true;
}

bool compiler_parse_logical_or(NanoSol_Compiler *compiler) {
  if (!compiler_parse_logical_and(compiler)) {
    return false;
  }
  while (compiler_match(compiler, TOKEN_OROR)) {
    size_t true_label = compiler_new_label(compiler);
    size_t end_label = compiler_new_label(compiler);
    if (true_label == SIZE_MAX || end_label == SIZE_MAX) {
      return false;
    }

    // Short-circuit: if lhs is true, keep it and skip rhs evaluation.
    if (!compiler_emit_booleanize_top(compiler) ||
        !compiler_emit_opcode(compiler, OPCODE_DUP1) ||
        !compiler_emit_jump(compiler, true_label, true) ||
        !compiler_emit_opcode(compiler, OPCODE_POP)) {
      return false;
    }

    if (!compiler_parse_logical_and(compiler) ||
        !compiler_emit_booleanize_top(compiler) ||
        !compiler_emit_jump(compiler, end_label, false) ||
        !compiler_mark_label(compiler, true_label) ||
        !compiler_mark_label(compiler, end_label)) {
      return false;
    }
  }
  return true;
}
