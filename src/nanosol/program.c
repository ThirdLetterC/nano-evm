#include <stdlib.h>
#include <string.h>

#include "nanosol/common_internal.h"
#include "nanosol/program_internal.h"
#include "nanosol/statement_internal.h"

static bool compiler_scan_expect(NanoSol_Compiler *compiler,
                                 NanoSol_Lexer *scan_lexer,
                                 NanoSol_Token *scan_token,
                                 NanoSol_TokenKind kind, const char *message) {
  if (scan_token->kind == TOKEN_INVALID) {
    compiler_set_error(compiler, NANOSOL_ERR_LEX, scan_token, "%s",
                       token_invalid_message(scan_token));
    return false;
  }
  if (scan_token->kind != kind) {
    compiler_set_error(compiler, NANOSOL_ERR_PARSE, scan_token, "%s", message);
    return false;
  }
  *scan_token = lexer_next_token(scan_lexer);
  return true;
}

static bool compiler_scan_parameter_count(NanoSol_Compiler *compiler,
                                          NanoSol_Lexer *scan_lexer,
                                          NanoSol_Token *scan_token,
                                          size_t *out_parameter_count) {
  size_t parameter_count = 0;

  if (scan_token->kind != TOKEN_RPAREN) {
    while (true) {
      if (scan_token->kind == TOKEN_KW_UINT ||
          scan_token->kind == TOKEN_KW_LET) {
        *scan_token = lexer_next_token(scan_lexer);
      }

      if (!compiler_scan_expect(compiler, scan_lexer, scan_token,
                                TOKEN_IDENTIFIER, "expected parameter name")) {
        return false;
      }

      parameter_count += 1U;
      if (scan_token->kind != TOKEN_COMMA) {
        break;
      }
      *scan_token = lexer_next_token(scan_lexer);
    }
  }

  if (!compiler_scan_expect(compiler, scan_lexer, scan_token, TOKEN_RPAREN,
                            "expected ')' after parameter list")) {
    return false;
  }

  *out_parameter_count = parameter_count;
  return true;
}

static bool compiler_scan_skip_function_body(NanoSol_Compiler *compiler,
                                             NanoSol_Lexer *scan_lexer,
                                             NanoSol_Token *scan_token) {
  if (scan_token->kind != TOKEN_LBRACE) {
    compiler_set_error(compiler, NANOSOL_ERR_PARSE, scan_token,
                       "expected '{' after function signature");
    return false;
  }

  size_t depth = 1U;
  *scan_token = lexer_next_token(scan_lexer);
  // Signature scan is lexical only: just balance braces and skip internals.
  while (depth > 0U) {
    if (scan_token->kind == TOKEN_INVALID) {
      compiler_set_error(compiler, NANOSOL_ERR_LEX, scan_token, "%s",
                         token_invalid_message(scan_token));
      return false;
    }
    if (scan_token->kind == TOKEN_EOF) {
      compiler_set_error(compiler, NANOSOL_ERR_PARSE, scan_token,
                         "expected '}' after function body");
      return false;
    }
    if (scan_token->kind == TOKEN_LBRACE) {
      depth += 1U;
    } else if (scan_token->kind == TOKEN_RBRACE) {
      depth -= 1U;
    }
    *scan_token = lexer_next_token(scan_lexer);
  }
  return true;
}

static bool compiler_collect_function_signatures(NanoSol_Compiler *compiler) {
  NanoSol_Lexer scan_lexer = {
      .source = compiler->source,
      .source_length = strlen(compiler->source),
      .position = 0,
      .line = 1,
      .column = 1,
      .has_unterminated_block_comment = false,
      .unterminated_comment_line = 0,
      .unterminated_comment_column = 0,
  };

  NanoSol_Token scan_token = lexer_next_token(&scan_lexer);
  // Pass 1: collect function names/arity so forward calls can be resolved.
  while (scan_token.kind != TOKEN_EOF) {
    if (scan_token.kind == TOKEN_INVALID) {
      compiler_set_error(compiler, NANOSOL_ERR_LEX, &scan_token, "%s",
                         token_invalid_message(&scan_token));
      return false;
    }
    if (scan_token.kind != TOKEN_KW_FUNCTION) {
      scan_token = lexer_next_token(&scan_lexer);
      continue;
    }

    scan_token = lexer_next_token(&scan_lexer);
    NanoSol_Token function_name = scan_token;
    if (!compiler_scan_expect(compiler, &scan_lexer, &scan_token,
                              TOKEN_IDENTIFIER, "expected function name")) {
      return false;
    }
    if (!compiler_scan_expect(compiler, &scan_lexer, &scan_token, TOKEN_LPAREN,
                              "expected '(' after function name")) {
      return false;
    }

    size_t parameter_count = 0;
    if (!compiler_scan_parameter_count(compiler, &scan_lexer, &scan_token,
                                       &parameter_count)) {
      return false;
    }

    if (!compiler_add_function_declaration(compiler, &function_name,
                                           parameter_count)) {
      return false;
    }

    if (!compiler_scan_skip_function_body(compiler, &scan_lexer, &scan_token)) {
      return false;
    }
  }

  return true;
}

static bool compiler_select_entry_function(NanoSol_Compiler *compiler) {
  if (compiler->functions_count == 0U) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current,
                       "no functions available for entrypoint");
    return false;
  }

  ptrdiff_t main_index = compiler_find_function_literal(compiler, "main");
  compiler->entry_function = (main_index >= 0) ? (size_t)main_index : 0U;
  return true;
}

static bool compiler_emit_initialize_frame_pointer(NanoSol_Compiler *compiler) {
  return compiler_emit_push_u64(compiler, 0) &&
         compiler_emit_push_size(compiler, FRAME_POINTER_SLOT_OFFSET) &&
         compiler_emit_opcode(compiler, OPCODE_MSTORE);
}

static bool compiler_emit_entrypoint_call(NanoSol_Compiler *compiler,
                                          size_t function_index,
                                          size_t return_label) {
  if (function_index >= compiler->functions_count) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "invalid entrypoint");
    return false;
  }

  if (!compiler_emit_allocate_call_frame(compiler)) {
    return false;
  }

  size_t parameter_count = compiler->functions[function_index].parameter_count;
  // ABI-style entrypoint: each argument is read from calldata word i.
  for (size_t i = 0; i < parameter_count; ++i) {
    size_t offset = i * LOCAL_SLOT_SIZE;
    if (!compiler_emit_push_size(compiler, offset) ||
        !compiler_emit_opcode(compiler, OPCODE_CALLDATALOAD) ||
        !compiler_emit_store_current_frame_slot(compiler, offset)) {
      return false;
    }
  }

  return compiler_emit_push_label(compiler, return_label) &&
         compiler_emit_jump(
             compiler, compiler->functions[function_index].label_index, false);
}

static bool compiler_parse_function(NanoSol_Compiler *compiler) {
  if (!compiler_expect(compiler, TOKEN_KW_FUNCTION, "expected 'function'")) {
    return false;
  }

  NanoSol_Token name = compiler->current;
  if (!compiler_expect(compiler, TOKEN_IDENTIFIER, "expected function name")) {
    return false;
  }

  ptrdiff_t function_index = compiler_find_function(compiler, &name);
  if (function_index < 0) {
    compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &name,
                       "unknown function declaration");
    return false;
  }
  if (compiler->functions[(size_t)function_index].defined) {
    compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &name,
                       "function already defined");
    return false;
  }

  if (!compiler_expect(compiler, TOKEN_LPAREN,
                       "expected '(' after function name")) {
    return false;
  }

  compiler_clear_locals(compiler);
  compiler->scope_depth = 1U;
  size_t parsed_parameter_count = 0;
  if (compiler->current.kind != TOKEN_RPAREN) {
    while (true) {
      if (compiler->current.kind == TOKEN_KW_UINT ||
          compiler->current.kind == TOKEN_KW_LET) {
        compiler->current = lexer_next_token(&compiler->lexer);
      }

      NanoSol_Token parameter_name = compiler->current;
      if (!compiler_expect(compiler, TOKEN_IDENTIFIER,
                           "expected parameter name")) {
        return false;
      }
      if (!compiler_add_local(compiler, &parameter_name)) {
        return false;
      }
      parsed_parameter_count += 1U;
      if (!compiler_match(compiler, TOKEN_COMMA)) {
        break;
      }
    }
  }
  if (!compiler_expect(compiler, TOKEN_RPAREN,
                       "expected ')' after parameter list")) {
    return false;
  }

  if (parsed_parameter_count !=
      compiler->functions[(size_t)function_index].parameter_count) {
    compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, &name,
                       "parameter count mismatch in function definition");
    return false;
  }

  compiler->scope_depth = 0;
  compiler->current_function = (size_t)function_index;
  compiler->functions[(size_t)function_index].defined = true;

  // Function prologue stores synthetic return address slot before body parse.
  if (!compiler_mark_label(
          compiler, compiler->functions[(size_t)function_index].label_index) ||
      !compiler_emit_store_current_frame_slot(
          compiler, FUNCTION_RETURN_ADDRESS_SLOT_OFFSET) ||
      !compiler_parse_block(compiler) || !compiler_emit_push_u64(compiler, 0) ||
      !compiler_emit_internal_function_return(compiler)) {
    return false;
  }

  compiler_clear_locals(compiler);
  compiler->scope_depth = 0;
  compiler->current_function = SIZE_MAX;
  return true;
}

bool compiler_parse_program(NanoSol_Compiler *compiler) {
  if (compiler->current.kind == TOKEN_INVALID) {
    compiler_set_error(compiler, NANOSOL_ERR_LEX, &compiler->current, "%s",
                       token_invalid_message(&compiler->current));
    return false;
  }

  if (!compiler_collect_function_signatures(compiler)) {
    return false;
  }

  if (compiler->functions_count > 0U) {
    // Function-mode program: emit dispatcher call, then parse declarations.
    if (!compiler_select_entry_function(compiler) ||
        !compiler_emit_initialize_frame_pointer(compiler)) {
      return false;
    }

    size_t entry_return_label = compiler_new_label(compiler);
    if (entry_return_label == SIZE_MAX) {
      return false;
    }
    if (!compiler_emit_entrypoint_call(compiler, compiler->entry_function,
                                       entry_return_label)) {
      return false;
    }

    if (compiler->current.kind == TOKEN_KW_CONTRACT) {
      compiler->current = lexer_next_token(&compiler->lexer);
      if (!compiler_expect(compiler, TOKEN_IDENTIFIER,
                           "expected contract name")) {
        return false;
      }
      if (!compiler_expect(compiler, TOKEN_LBRACE,
                           "expected '{' after contract name")) {
        return false;
      }
      while (compiler->current.kind != TOKEN_RBRACE &&
             compiler->current.kind != TOKEN_EOF) {
        if (compiler->current.kind != TOKEN_KW_FUNCTION) {
          compiler_set_error(compiler, NANOSOL_ERR_PARSE, &compiler->current,
                             "expected function declaration in contract body");
          return false;
        }
        if (!compiler_parse_function(compiler)) {
          return false;
        }
      }
      if (!compiler_expect(compiler, TOKEN_RBRACE,
                           "expected '}' after contract body")) {
        return false;
      }
    } else {
      while (compiler->current.kind == TOKEN_KW_FUNCTION) {
        if (!compiler_parse_function(compiler)) {
          return false;
        }
      }
    }

    if (!compiler_expect(compiler, TOKEN_EOF, "expected end of input") ||
        !compiler_mark_label(compiler, entry_return_label)) {
      return false;
    }
    return compiler_emit_external_word_return(compiler);
  }

  // Script-mode program: parse top-level statements directly.
  if (!compiler_emit_initialize_frame_pointer(compiler) ||
      !compiler_emit_allocate_call_frame(compiler)) {
    return false;
  }

  while (compiler->current.kind != TOKEN_EOF) {
    if (!compiler_parse_statement(compiler)) {
      return false;
    }
  }

  if (!compiler_expect(compiler, TOKEN_EOF, "expected end of input")) {
    return false;
  }

  return compiler_emit_opcode(compiler, OPCODE_STOP);
}

void compiler_destroy(NanoSol_Compiler *compiler) {
  compiler_clear_locals(compiler);
  free(compiler->locals);
  for (size_t i = 0; i < compiler->functions_count; ++i) {
    free(compiler->functions[i].name);
  }
  free(compiler->functions);
  free(compiler->labels);
  free(compiler->patches);
  free(compiler->bytecode.bytes);
}

void compiler_init(NanoSol_Compiler *compiler, const char *source, char *error,
                   size_t error_size) {
  memset(compiler, 0, sizeof(*compiler));
  compiler->source = source;
  compiler->status = NANOSOL_OK;
  compiler->error = error;
  compiler->error_size = error_size;
  compiler->lexer.source = source;
  compiler->lexer.source_length = strlen(source);
  compiler->lexer.position = 0;
  compiler->lexer.line = 1;
  compiler->lexer.column = 1;
  compiler->lexer.has_unterminated_block_comment = false;
  compiler->lexer.unterminated_comment_line = 0;
  compiler->lexer.unterminated_comment_column = 0;
  compiler->current_function = SIZE_MAX;
  compiler->entry_function = SIZE_MAX;
  compiler->scope_depth = 0;
  compiler->current = lexer_next_token(&compiler->lexer);
}
