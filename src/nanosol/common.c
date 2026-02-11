#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#define NANOSOL_HAVE_STDCKDINT 1
#endif
#endif

#ifndef NANOSOL_HAVE_STDCKDINT
#define NANOSOL_HAVE_STDCKDINT 0
#endif

#include "nanosol/common_internal.h"
#include "nanosol/expression_internal.h"

static bool checked_add_size(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return false;
  }
#if NANOSOL_HAVE_STDCKDINT
  return !ckd_add(out, a, b);
#else
  if (a > SIZE_MAX - b) {
    return false;
  }
  *out = a + b;
  return true;
#endif
}

static bool checked_mul_size(size_t a, size_t b, size_t *out) {
  if (out == nullptr) {
    return false;
  }
#if NANOSOL_HAVE_STDCKDINT
  return !ckd_mul(out, a, b);
#else
  if (a != 0U && b > (SIZE_MAX / a)) {
    return false;
  }
  *out = a * b;
  return true;
#endif
}

static NanoSol_Token token_make(NanoSol_TokenKind kind, size_t start,
                                size_t length, size_t line, size_t column) {
  NanoSol_Token token = {
      .kind = kind,
      .start = start,
      .length = length,
      .line = line,
      .column = column,
      .number = 0,
      .number_overflow = false,
      .unterminated_block_comment = false,
  };
  return token;
}

const char *token_invalid_message(const NanoSol_Token *token) {
  if (token != nullptr && token->unterminated_block_comment) {
    return "unterminated block comment";
  }
  return "invalid token";
}

static bool is_ident_start(char c) {
  return (c == '_') || isalpha((unsigned char)c);
}

static bool is_ident_continue(char c) {
  return (c == '_') || isalnum((unsigned char)c);
}

static void lexer_advance(NanoSol_Lexer *lexer) {
  if (lexer->position >= lexer->source_length) {
    return;
  }

  char c = lexer->source[lexer->position];
  lexer->position += 1U;
  if (c == '\n') {
    lexer->line += 1U;
    lexer->column = 1;
  } else {
    lexer->column += 1U;
  }
}

static char lexer_peek(const NanoSol_Lexer *lexer) {
  if (lexer->position >= lexer->source_length) {
    return '\0';
  }
  return lexer->source[lexer->position];
}

static char lexer_peek_next(const NanoSol_Lexer *lexer) {
  size_t next = lexer->position + 1U;
  if (next >= lexer->source_length) {
    return '\0';
  }
  return lexer->source[next];
}

static bool lexer_match(NanoSol_Lexer *lexer, char expected) {
  if (lexer_peek(lexer) != expected) {
    return false;
  }
  lexer_advance(lexer);
  return true;
}

static void lexer_skip_whitespace_and_comments(NanoSol_Lexer *lexer) {
  while (true) {
    char c = lexer_peek(lexer);
    if (c == '\0') {
      return;
    }

    if (isspace((unsigned char)c)) {
      lexer_advance(lexer);
      continue;
    }

    if (c == '/' && lexer_peek_next(lexer) == '/') {
      lexer_advance(lexer);
      lexer_advance(lexer);
      while (true) {
        char line_c = lexer_peek(lexer);
        if (line_c == '\0' || line_c == '\n') {
          break;
        }
        lexer_advance(lexer);
      }
      continue;
    }

    if (c == '/' && lexer_peek_next(lexer) == '*') {
      size_t comment_line = lexer->line;
      size_t comment_column = lexer->column;
      lexer_advance(lexer);
      lexer_advance(lexer);
      while (true) {
        char block_c = lexer_peek(lexer);
        if (block_c == '\0') {
          // Defer reporting so the caller gets a regular TOKEN_INVALID with the
          // original comment start location.
          lexer->has_unterminated_block_comment = true;
          lexer->unterminated_comment_line = comment_line;
          lexer->unterminated_comment_column = comment_column;
          return;
        }
        if (block_c == '*' && lexer_peek_next(lexer) == '/') {
          lexer_advance(lexer);
          lexer_advance(lexer);
          break;
        }
        lexer_advance(lexer);
      }
      continue;
    }
    return;
  }
}

static NanoSol_TokenKind keyword_or_identifier(const char *text,
                                               size_t length) {
  if (length == 8 && memcmp(text, "contract", 8) == 0) {
    return TOKEN_KW_CONTRACT;
  }
  if (length == 8 && memcmp(text, "function", 8) == 0) {
    return TOKEN_KW_FUNCTION;
  }
  if (length == 6 && memcmp(text, "return", 6) == 0) {
    return TOKEN_KW_RETURN;
  }
  if (length == 3 && memcmp(text, "let", 3) == 0) {
    return TOKEN_KW_LET;
  }
  if (length == 4 && memcmp(text, "uint", 4) == 0) {
    return TOKEN_KW_UINT;
  }
  if (length == 2 && memcmp(text, "if", 2) == 0) {
    return TOKEN_KW_IF;
  }
  if (length == 4 && memcmp(text, "else", 4) == 0) {
    return TOKEN_KW_ELSE;
  }
  if (length == 5 && memcmp(text, "while", 5) == 0) {
    return TOKEN_KW_WHILE;
  }
  if (length == 4 && memcmp(text, "true", 4) == 0) {
    return TOKEN_KW_TRUE;
  }
  if (length == 5 && memcmp(text, "false", 5) == 0) {
    return TOKEN_KW_FALSE;
  }
  return TOKEN_IDENTIFIER;
}

static NanoSol_Token lex_number(NanoSol_Lexer *lexer) {
  size_t start = lexer->position;
  size_t line = lexer->line;
  size_t column = lexer->column;
  bool overflow = false;
  uint64_t value = 0;

  int base = 10;
  if (lexer_peek(lexer) == '0') {
    char next = lexer_peek_next(lexer);
    if (next == 'x' || next == 'X') {
      base = 16;
      lexer_advance(lexer);
      lexer_advance(lexer);
    }
  }

  bool any_digit = false;
  while (true) {
    char c = lexer_peek(lexer);
    if (c == '_') {
      lexer_advance(lexer);
      continue;
    }

    int digit = -1;
    if (base == 10) {
      if (c >= '0' && c <= '9') {
        digit = c - '0';
      }
    } else {
      if (c >= '0' && c <= '9') {
        digit = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        digit = 10 + (c - 'a');
      } else if (c >= 'A' && c <= 'F') {
        digit = 10 + (c - 'A');
      }
    }

    if (digit < 0) {
      break;
    }

    any_digit = true;
    // Keep a fast u64 value for simple literals; full uint256 parsing happens
    // later in compiler_emit_push_numeric_literal.
    if (!overflow) {
      if (value > (UINT64_MAX - (uint64_t)digit) / (uint64_t)base) {
        overflow = true;
      } else {
        value = value * (uint64_t)base + (uint64_t)digit;
      }
    }
    lexer_advance(lexer);
  }

  NanoSol_Token token =
      token_make(TOKEN_NUMBER, start, lexer->position - start, line, column);
  token.number = value;
  token.number_overflow = overflow || !any_digit;
  return token;
}

NanoSol_Token lexer_next_token(NanoSol_Lexer *lexer) {
  lexer_skip_whitespace_and_comments(lexer);
  if (lexer->has_unterminated_block_comment) {
    lexer->has_unterminated_block_comment = false;
    NanoSol_Token token = token_make(TOKEN_INVALID, lexer->position, 0U,
                                     lexer->unterminated_comment_line,
                                     lexer->unterminated_comment_column);
    token.unterminated_block_comment = true;
    return token;
  }

  size_t start = lexer->position;
  size_t line = lexer->line;
  size_t column = lexer->column;
  char c = lexer_peek(lexer);
  if (c == '\0') {
    return token_make(TOKEN_EOF, start, 0, line, column);
  }

  if (is_ident_start(c)) {
    lexer_advance(lexer);
    while (is_ident_continue(lexer_peek(lexer))) {
      lexer_advance(lexer);
    }
    size_t length = lexer->position - start;
    NanoSol_TokenKind kind =
        keyword_or_identifier(&lexer->source[start], length);
    return token_make(kind, start, length, line, column);
  }

  if (isdigit((unsigned char)c)) {
    return lex_number(lexer);
  }

  lexer_advance(lexer);
  switch (c) {
  case '{':
    return token_make(TOKEN_LBRACE, start, 1, line, column);
  case '}':
    return token_make(TOKEN_RBRACE, start, 1, line, column);
  case '(':
    return token_make(TOKEN_LPAREN, start, 1, line, column);
  case ')':
    return token_make(TOKEN_RPAREN, start, 1, line, column);
  case ';':
    return token_make(TOKEN_SEMICOLON, start, 1, line, column);
  case ',':
    return token_make(TOKEN_COMMA, start, 1, line, column);
  case '+':
    return token_make(TOKEN_PLUS, start, 1, line, column);
  case '-':
    return token_make(TOKEN_MINUS, start, 1, line, column);
  case '*':
    return token_make(TOKEN_STAR, start, 1, line, column);
  case '/':
    return token_make(TOKEN_SLASH, start, 1, line, column);
  case '%':
    return token_make(TOKEN_PERCENT, start, 1, line, column);
  case '!':
    if (lexer_match(lexer, '=')) {
      return token_make(TOKEN_NEQ, start, 2, line, column);
    }
    return token_make(TOKEN_BANG, start, 1, line, column);
  case '=':
    if (lexer_match(lexer, '=')) {
      return token_make(TOKEN_EQEQ, start, 2, line, column);
    }
    return token_make(TOKEN_ASSIGN, start, 1, line, column);
  case '<':
    if (lexer_match(lexer, '=')) {
      return token_make(TOKEN_LE, start, 2, line, column);
    }
    if (lexer_match(lexer, '<')) {
      return token_make(TOKEN_SHL, start, 2, line, column);
    }
    return token_make(TOKEN_LT, start, 1, line, column);
  case '>':
    if (lexer_match(lexer, '=')) {
      return token_make(TOKEN_GE, start, 2, line, column);
    }
    if (lexer_match(lexer, '>')) {
      return token_make(TOKEN_SHR, start, 2, line, column);
    }
    return token_make(TOKEN_GT, start, 1, line, column);
  case '&':
    if (lexer_match(lexer, '&')) {
      return token_make(TOKEN_ANDAND, start, 2, line, column);
    }
    return token_make(TOKEN_BITAND, start, 1, line, column);
  case '|':
    if (lexer_match(lexer, '|')) {
      return token_make(TOKEN_OROR, start, 2, line, column);
    }
    return token_make(TOKEN_BITOR, start, 1, line, column);
  case '^':
    return token_make(TOKEN_BITXOR, start, 1, line, column);
  default:
    return token_make(TOKEN_INVALID, start, 1, line, column);
  }
}

void compiler_set_error(NanoSol_Compiler *compiler, NanoSol_Status status,
                        const NanoSol_Token *token, const char *fmt, ...) {
  if (compiler->status != NANOSOL_OK) {
    return;
  }

  compiler->status = status;
  if (compiler->error == nullptr || compiler->error_size == 0) {
    return;
  }

  char detail[256];
  va_list args;
  va_start(args, fmt);
  int detail_len = vsnprintf(detail, sizeof(detail), fmt, args);
  va_end(args);
  if (detail_len < 0) {
    detail[0] = '\0';
  }

  if (token != nullptr) {
    (void)snprintf(compiler->error, compiler->error_size, "line %zu:%zu: %s",
                   token->line, token->column, detail);
  } else {
    (void)snprintf(compiler->error, compiler->error_size, "%s", detail);
  }
}

static bool compiler_reserve_bytes(NanoSol_Compiler *compiler,
                                   size_t required) {
  if (compiler->status != NANOSOL_OK) {
    return false;
  }

  if (required <= compiler->bytecode.capacity) {
    return true;
  }

  size_t new_capacity =
      (compiler->bytecode.capacity == 0) ? 64 : compiler->bytecode.capacity;
  while (new_capacity < required) {
    if (new_capacity > SIZE_MAX / 2U) {
      compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                         &compiler->current, "bytecode exceeds address space");
      return false;
    }
    new_capacity *= 2U;
  }

  size_t new_size = 0U;
  if (!checked_mul_size(new_capacity, sizeof(uint8_t), &new_size)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "bytecode exceeds address space");
    return false;
  }

  uint8_t *new_bytes = realloc(compiler->bytecode.bytes, new_size);
  if (new_bytes == nullptr) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_ALLOC, &compiler->current,
                       "out of memory");
    return false;
  }

  compiler->bytecode.bytes = new_bytes;
  compiler->bytecode.capacity = new_capacity;
  return true;
}

static bool compiler_emit_byte(NanoSol_Compiler *compiler, uint8_t byte) {
  size_t required = 0U;
  if (!checked_add_size(compiler->bytecode.size, 1U, &required)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "bytecode exceeds address space");
    return false;
  }
  if (!compiler_reserve_bytes(compiler, required)) {
    return false;
  }
  compiler->bytecode.bytes[compiler->bytecode.size] = byte;
  compiler->bytecode.size += 1U;
  return true;
}

bool compiler_emit_opcode(NanoSol_Compiler *compiler, uint8_t opcode) {
  return compiler_emit_byte(compiler, opcode);
}

bool compiler_emit_push_u64(NanoSol_Compiler *compiler, uint64_t value) {
  if (value == 0) {
    return compiler_emit_opcode(compiler, OPCODE_PUSH0);
  }

  // Emit the smallest PUSHn encoding for this immediate.
  size_t byte_count = 0;
  uint64_t temp = value;
  while (temp != 0) {
    byte_count += 1U;
    temp >>= 8U;
  }
  if (byte_count == 0 || byte_count > 32) {
    compiler_set_error(compiler, NANOSOL_ERR_EMIT, &compiler->current,
                       "invalid PUSH width");
    return false;
  }

  if (!compiler_emit_opcode(compiler,
                            (uint8_t)(OPCODE_PUSH1 + byte_count - 1U))) {
    return false;
  }

  for (size_t i = 0; i < byte_count; ++i) {
    size_t shift = (byte_count - 1U - i) * 8U;
    uint8_t immediate = (uint8_t)((value >> shift) & 0xffU);
    if (!compiler_emit_byte(compiler, immediate)) {
      return false;
    }
  }
  return true;
}

bool compiler_emit_push_size(NanoSol_Compiler *compiler, size_t value) {
#if SIZE_MAX > UINT64_MAX
  if (value > UINT64_MAX) {
    compiler_set_error(compiler, NANOSOL_ERR_EMIT, &compiler->current,
                       "value too large for PUSH immediate");
    return false;
  }
#endif
  return compiler_emit_push_u64(compiler, (uint64_t)value);
}

static bool
compiler_emit_push_current_frame_pointer(NanoSol_Compiler *compiler) {
  return compiler_emit_push_size(compiler, FRAME_POINTER_SLOT_OFFSET) &&
         compiler_emit_opcode(compiler, OPCODE_MLOAD);
}

static bool
compiler_emit_push_current_frame_slot_address(NanoSol_Compiler *compiler,
                                              size_t slot_offset) {
  return compiler_emit_push_current_frame_pointer(compiler) &&
         compiler_emit_push_size(compiler, slot_offset) &&
         compiler_emit_opcode(compiler, OPCODE_ADD);
}

bool compiler_emit_store_current_frame_slot(NanoSol_Compiler *compiler,
                                            size_t slot_offset) {
  return compiler_emit_push_current_frame_slot_address(compiler, slot_offset) &&
         compiler_emit_opcode(compiler, OPCODE_MSTORE);
}

bool compiler_emit_load_current_frame_slot(NanoSol_Compiler *compiler,
                                           size_t slot_offset) {
  return compiler_emit_push_current_frame_slot_address(compiler, slot_offset) &&
         compiler_emit_opcode(compiler, OPCODE_MLOAD);
}

bool compiler_emit_allocate_call_frame(NanoSol_Compiler *compiler) {
  // Frame pointer is stored in memory[FRAME_POINTER_SLOT_OFFSET].
  return compiler_emit_push_current_frame_pointer(compiler) &&
         compiler_emit_push_size(compiler, FUNCTION_FRAME_SIZE) &&
         compiler_emit_opcode(compiler, OPCODE_ADD) &&
         compiler_emit_push_size(compiler, FRAME_POINTER_SLOT_OFFSET) &&
         compiler_emit_opcode(compiler, OPCODE_MSTORE);
}

static bool compiler_emit_release_call_frame(NanoSol_Compiler *compiler) {
  // Mirror of allocate_call_frame: restore caller frame base.
  return compiler_emit_push_current_frame_pointer(compiler) &&
         compiler_emit_push_size(compiler, FUNCTION_FRAME_SIZE) &&
         compiler_emit_opcode(compiler, OPCODE_SUB) &&
         compiler_emit_push_size(compiler, FRAME_POINTER_SLOT_OFFSET) &&
         compiler_emit_opcode(compiler, OPCODE_MSTORE);
}

static bool compiler_reserve_locals(NanoSol_Compiler *compiler,
                                    size_t required) {
  if (required <= compiler->locals_capacity) {
    return true;
  }

  size_t new_capacity =
      (compiler->locals_capacity == 0) ? 8 : compiler->locals_capacity;
  while (new_capacity < required) {
    if (new_capacity > SIZE_MAX / 2U) {
      compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                         &compiler->current, "local table too large");
      return false;
    }
    new_capacity *= 2U;
  }

  size_t new_size = 0U;
  if (!checked_mul_size(new_capacity, sizeof(NanoSol_Local), &new_size)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "local table too large");
    return false;
  }

  NanoSol_Local *new_locals = realloc(compiler->locals, new_size);
  if (new_locals == nullptr) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_ALLOC, &compiler->current,
                       "out of memory");
    return false;
  }
  compiler->locals = new_locals;
  compiler->locals_capacity = new_capacity;
  return true;
}

void compiler_pop_locals_to_scope_depth(NanoSol_Compiler *compiler,
                                        size_t max_scope_depth) {
  while (compiler->locals_count > 0 &&
         compiler->locals[compiler->locals_count - 1U].scope_depth >
             max_scope_depth) {
    size_t index = compiler->locals_count - 1U;
    free(compiler->locals[index].name);
    compiler->locals[index].name = nullptr;
    compiler->locals[index].name_length = 0;
    compiler->locals[index].slot_offset = 0;
    compiler->locals[index].scope_depth = 0;
    compiler->locals_count = index;
  }
}

void compiler_clear_locals(NanoSol_Compiler *compiler) {
  compiler_pop_locals_to_scope_depth(compiler, 0);
  while (compiler->locals_count > 0) {
    size_t index = compiler->locals_count - 1U;
    free(compiler->locals[index].name);
    compiler->locals[index].name = nullptr;
    compiler->locals[index].name_length = 0;
    compiler->locals[index].slot_offset = 0;
    compiler->locals[index].scope_depth = 0;
    compiler->locals_count = index;
  }
}

ptrdiff_t compiler_find_local(const NanoSol_Compiler *compiler,
                              const NanoSol_Token *token) {
  // Reverse walk preserves lexical shadowing semantics.
  for (size_t i = compiler->locals_count; i > 0; --i) {
    size_t index = i - 1U;
    if (compiler->locals[index].name_length == token->length &&
        memcmp(compiler->locals[index].name, &compiler->source[token->start],
               token->length) == 0) {
      return (ptrdiff_t)index;
    }
  }
  return -1;
}

bool compiler_add_local(NanoSol_Compiler *compiler,
                        const NanoSol_Token *name_token) {
  for (size_t i = compiler->locals_count; i > 0; --i) {
    size_t index = i - 1U;
    if (compiler->locals[index].scope_depth < compiler->scope_depth) {
      break;
    }
    if (compiler->locals[index].scope_depth == compiler->scope_depth &&
        compiler->locals[index].name_length == name_token->length &&
        memcmp(compiler->locals[index].name,
               &compiler->source[name_token->start], name_token->length) == 0) {
      compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, name_token,
                         "variable already declared in this scope");
      return false;
    }
  }

  size_t required_locals = 0U;
  if (!checked_add_size(compiler->locals_count, 1U, &required_locals)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL, name_token,
                       "local table too large");
    return false;
  }
  if (!compiler_reserve_locals(compiler, required_locals)) {
    return false;
  }

  size_t name_length = name_token->length;
  size_t name_storage = 0U;
  if (!checked_add_size(name_length, 1U, &name_storage)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL, name_token,
                       "identifier too long");
    return false;
  }
  char *name_copy = calloc(name_storage, sizeof(char));
  if (name_copy == nullptr) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_ALLOC, name_token,
                       "out of memory");
    return false;
  }
  memcpy(name_copy, &compiler->source[name_token->start], name_length);

  if (compiler->locals_count >= FUNCTION_MAX_LOCAL_SLOTS) {
    free(name_copy);
    compiler_set_error(compiler, NANOSOL_ERR_EMIT, name_token,
                       "too many locals in function");
    return false;
  }
  // Locals are fixed-width 32-byte slots in the current function frame.
  size_t slot_offset = compiler->locals_count * LOCAL_SLOT_SIZE;

  compiler->locals[compiler->locals_count].name = name_copy;
  compiler->locals[compiler->locals_count].name_length = name_length;
  compiler->locals[compiler->locals_count].slot_offset = slot_offset;
  compiler->locals[compiler->locals_count].scope_depth = compiler->scope_depth;
  compiler->locals_count += 1U;
  return true;
}

static bool compiler_reserve_functions(NanoSol_Compiler *compiler,
                                       size_t required) {
  if (required <= compiler->functions_capacity) {
    return true;
  }

  size_t new_capacity =
      (compiler->functions_capacity == 0) ? 8 : compiler->functions_capacity;
  while (new_capacity < required) {
    if (new_capacity > SIZE_MAX / 2U) {
      compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                         &compiler->current, "function table too large");
      return false;
    }
    new_capacity *= 2U;
  }

  size_t new_size = 0U;
  if (!checked_mul_size(new_capacity, sizeof(NanoSol_Function), &new_size)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "function table too large");
    return false;
  }

  NanoSol_Function *new_functions = realloc(compiler->functions, new_size);
  if (new_functions == nullptr) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_ALLOC, &compiler->current,
                       "out of memory");
    return false;
  }
  compiler->functions = new_functions;
  compiler->functions_capacity = new_capacity;
  return true;
}

ptrdiff_t compiler_find_function(const NanoSol_Compiler *compiler,
                                 const NanoSol_Token *token) {
  for (size_t i = 0; i < compiler->functions_count; ++i) {
    if (compiler->functions[i].name_length == token->length &&
        memcmp(compiler->functions[i].name, &compiler->source[token->start],
               token->length) == 0) {
      return (ptrdiff_t)i;
    }
  }
  return -1;
}

ptrdiff_t compiler_find_function_literal(const NanoSol_Compiler *compiler,
                                         const char *name) {
  size_t name_length = strlen(name);
  for (size_t i = 0; i < compiler->functions_count; ++i) {
    if (compiler->functions[i].name_length == name_length &&
        memcmp(compiler->functions[i].name, name, name_length) == 0) {
      return (ptrdiff_t)i;
    }
  }
  return -1;
}

bool compiler_add_function_declaration(NanoSol_Compiler *compiler,
                                       const NanoSol_Token *name_token,
                                       size_t parameter_count) {
  if (compiler_find_function(compiler, name_token) >= 0) {
    compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, name_token,
                       "function already declared");
    return false;
  }

  size_t required_functions = 0U;
  if (!checked_add_size(compiler->functions_count, 1U, &required_functions)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL, name_token,
                       "function table too large");
    return false;
  }
  if (!compiler_reserve_functions(compiler, required_functions)) {
    return false;
  }

  size_t name_length = name_token->length;
  size_t name_storage = 0U;
  if (!checked_add_size(name_length, 1U, &name_storage)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL, name_token,
                       "identifier too long");
    return false;
  }
  char *name_copy = calloc(name_storage, sizeof(char));
  if (name_copy == nullptr) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_ALLOC, name_token,
                       "out of memory");
    return false;
  }
  memcpy(name_copy, &compiler->source[name_token->start], name_length);

  // Predeclare entry label so calls can target functions before definition.
  size_t label_index = compiler_new_label(compiler);
  if (label_index == SIZE_MAX) {
    free(name_copy);
    return false;
  }

  compiler->functions[compiler->functions_count].name = name_copy;
  compiler->functions[compiler->functions_count].name_length = name_length;
  compiler->functions[compiler->functions_count].parameter_count =
      parameter_count;
  compiler->functions[compiler->functions_count].label_index = label_index;
  compiler->functions[compiler->functions_count].defined = false;
  compiler->functions_count += 1U;
  return true;
}

static bool compiler_reserve_labels(NanoSol_Compiler *compiler,
                                    size_t required) {
  if (required <= compiler->labels_capacity) {
    return true;
  }

  size_t new_capacity =
      (compiler->labels_capacity == 0) ? 8 : compiler->labels_capacity;
  while (new_capacity < required) {
    if (new_capacity > SIZE_MAX / 2U) {
      compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                         &compiler->current, "too many labels");
      return false;
    }
    new_capacity *= 2U;
  }

  size_t new_size = 0U;
  if (!checked_mul_size(new_capacity, sizeof(NanoSol_Label), &new_size)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "too many labels");
    return false;
  }

  NanoSol_Label *new_labels = realloc(compiler->labels, new_size);
  if (new_labels == nullptr) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_ALLOC, &compiler->current,
                       "out of memory");
    return false;
  }
  compiler->labels = new_labels;
  compiler->labels_capacity = new_capacity;
  return true;
}

static bool compiler_reserve_patches(NanoSol_Compiler *compiler,
                                     size_t required) {
  if (required <= compiler->patches_capacity) {
    return true;
  }

  size_t new_capacity =
      (compiler->patches_capacity == 0) ? 8 : compiler->patches_capacity;
  while (new_capacity < required) {
    if (new_capacity > SIZE_MAX / 2U) {
      compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                         &compiler->current, "too many jumps");
      return false;
    }
    new_capacity *= 2U;
  }

  size_t new_size = 0U;
  if (!checked_mul_size(new_capacity, sizeof(NanoSol_Patch), &new_size)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "too many jumps");
    return false;
  }

  NanoSol_Patch *new_patches = realloc(compiler->patches, new_size);
  if (new_patches == nullptr) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_ALLOC, &compiler->current,
                       "out of memory");
    return false;
  }
  compiler->patches = new_patches;
  compiler->patches_capacity = new_capacity;
  return true;
}

size_t compiler_new_label(NanoSol_Compiler *compiler) {
  size_t required_labels = 0U;
  if (!checked_add_size(compiler->labels_count, 1U, &required_labels) ||
      !compiler_reserve_labels(compiler, required_labels)) {
    return SIZE_MAX;
  }
  size_t label_index = compiler->labels_count;
  compiler->labels[label_index].defined = false;
  compiler->labels[label_index].address = 0;
  compiler->labels_count += 1U;
  return label_index;
}

bool compiler_mark_label(NanoSol_Compiler *compiler, size_t label_index) {
  if (label_index >= compiler->labels_count) {
    compiler_set_error(compiler, NANOSOL_ERR_EMIT, &compiler->current,
                       "invalid label id");
    return false;
  }

  if (compiler->labels[label_index].defined) {
    compiler_set_error(compiler, NANOSOL_ERR_EMIT, &compiler->current,
                       "label defined more than once");
    return false;
  }

  compiler->labels[label_index].defined = true;
  compiler->labels[label_index].address = compiler->bytecode.size;
  return compiler_emit_opcode(compiler, OPCODE_JUMPDEST);
}

bool compiler_emit_push_label(NanoSol_Compiler *compiler, size_t label_index) {
  if (label_index >= compiler->labels_count) {
    compiler_set_error(compiler, NANOSOL_ERR_EMIT, &compiler->current,
                       "invalid label id");
    return false;
  }

  size_t required_patches = 0U;
  if (!checked_add_size(compiler->patches_count, 1U, &required_patches)) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "too many jumps");
    return false;
  }
  if (!compiler_reserve_patches(compiler, required_patches)) {
    return false;
  }

  if (!compiler_emit_opcode(
          compiler,
          (uint8_t)(OPCODE_PUSH1 + JUMP_LABEL_IMMEDIATE_BYTES - 1U))) {
    return false;
  }
  // Reserve immediate bytes now and patch real jump destinations later.
  size_t patch_offset = compiler->bytecode.size;
  for (size_t i = 0; i < JUMP_LABEL_IMMEDIATE_BYTES; ++i) {
    if (!compiler_emit_byte(compiler, 0)) {
      return false;
    }
  }

  compiler->patches[compiler->patches_count].patch_offset = patch_offset;
  compiler->patches[compiler->patches_count].label_index = label_index;
  compiler->patches_count += 1U;
  return true;
}

bool compiler_emit_jump(NanoSol_Compiler *compiler, size_t label_index,
                        bool conditional) {
  if (!compiler_emit_push_label(compiler, label_index)) {
    return false;
  }
  return compiler_emit_opcode(compiler,
                              conditional ? OPCODE_JUMPI : OPCODE_JUMP);
}

bool compiler_patch_labels(NanoSol_Compiler *compiler) {
  // Second pass: replace PUSH4 placeholders with final bytecode addresses.
  for (size_t i = 0; i < compiler->patches_count; ++i) {
    size_t label_index = compiler->patches[i].label_index;
    if (label_index >= compiler->labels_count ||
        !compiler->labels[label_index].defined) {
      compiler_set_error(compiler, NANOSOL_ERR_EMIT, &compiler->current,
                         "unresolved jump label");
      return false;
    }

    size_t address = compiler->labels[label_index].address;
    if (address > UINT32_MAX) {
      compiler_set_error(compiler, NANOSOL_ERR_EMIT, &compiler->current,
                         "bytecode exceeds PUSH4 jumps");
      return false;
    }

    size_t patch_offset = compiler->patches[i].patch_offset;
    compiler->bytecode.bytes[patch_offset] =
        (uint8_t)((address >> 24U) & 0xffU);
    compiler->bytecode.bytes[patch_offset + 1U] =
        (uint8_t)((address >> 16U) & 0xffU);
    compiler->bytecode.bytes[patch_offset + 2U] =
        (uint8_t)((address >> 8U) & 0xffU);
    compiler->bytecode.bytes[patch_offset + 3U] = (uint8_t)(address & 0xffU);
  }
  return true;
}

bool compiler_match(NanoSol_Compiler *compiler, NanoSol_TokenKind kind) {
  if (compiler->current.kind != kind) {
    return false;
  }
  compiler->current = lexer_next_token(&compiler->lexer);
  return true;
}

bool compiler_expect(NanoSol_Compiler *compiler, NanoSol_TokenKind kind,
                     const char *message) {
  if (compiler->current.kind == TOKEN_INVALID) {
    compiler_set_error(compiler, NANOSOL_ERR_LEX, &compiler->current, "%s",
                       token_invalid_message(&compiler->current));
    return false;
  }
  if (compiler->current.kind != kind) {
    compiler_set_error(compiler, NANOSOL_ERR_PARSE, &compiler->current, "%s",
                       message);
    return false;
  }
  compiler->current = lexer_next_token(&compiler->lexer);
  return true;
}

bool compiler_identifier_equals(const NanoSol_Compiler *compiler,
                                const NanoSol_Token *token,
                                const char *literal) {
  size_t literal_length = strlen(literal);
  return token->length == literal_length &&
         memcmp(&compiler->source[token->start], literal, literal_length) == 0;
}

bool compiler_emit_booleanize_top(NanoSol_Compiler *compiler) {
  return compiler_emit_opcode(compiler, OPCODE_ISZERO) &&
         compiler_emit_opcode(compiler, OPCODE_ISZERO);
}

bool compiler_parse_expression(NanoSol_Compiler *compiler) {
  return compiler_parse_logical_or(compiler);
}

static const NanoSol_BuiltinSpec EXPRESSION_BUILTINS[] = {
    {"address", 0, OPCODE_ADDRESS, false},
    {"origin", 0, OPCODE_ORIGIN, false},
    {"caller", 0, OPCODE_CALLER, false},
    {"callvalue", 0, OPCODE_CALLVALUE, false},
    {"gasprice", 0, OPCODE_GASPRICE, false},
    {"timestamp", 0, OPCODE_TIMESTAMP, false},
    {"number", 0, OPCODE_NUMBER, false},
    {"chainid", 0, OPCODE_CHAINID, false},
    {"selfbalance", 0, OPCODE_SELFBALANCE, false},
    {"basefee", 0, OPCODE_BASEFEE, false},
    {"gas", 0, OPCODE_GAS, false},
    {"codesize", 0, OPCODE_CODESIZE, false},
    {"calldatasize", 0, OPCODE_CALLDATASIZE, false},
    {"coinbase", 0, OPCODE_COINBASE, false},
    {"prevrandao", 0, OPCODE_PREVRANDAO, false},
    {"gaslimit", 0, OPCODE_GASLIMIT, false},
    {"blobbasefee", 0, OPCODE_BLOBBASEFEE, false},
    {"pc", 0, OPCODE_PC, false},
    {"msize", 0, OPCODE_MSIZE, false},
    {"returndatasize", 0, OPCODE_RETURNDATASIZE, false},
    {"sload", 1, OPCODE_SLOAD, false},
    {"tload", 1, OPCODE_TLOAD, false},
    {"mload", 1, OPCODE_MLOAD, false},
    {"calldataload", 1, OPCODE_CALLDATALOAD, false},
    {"balance", 1, OPCODE_BALANCE, false},
    {"extcodesize", 1, OPCODE_EXTCODESIZE, false},
    {"extcodehash", 1, OPCODE_EXTCODEHASH, false},
    {"blockhash", 1, OPCODE_BLOCKHASH, false},
    {"iszero", 1, OPCODE_ISZERO, false},
    {"not", 1, OPCODE_NOT, false},
    {"byte", 2, OPCODE_BYTE, false},
    {"exp", 2, OPCODE_EXP, false},
    {"signextend", 2, OPCODE_SIGNEXTEND, false},
    {"keccak256", 2, OPCODE_KECCAK256, true},
    {"addmod", 3, OPCODE_ADDMOD, false},
    {"mulmod", 3, OPCODE_MULMOD, false},
};

const NanoSol_BuiltinSpec *
compiler_find_expression_builtin(const NanoSol_Compiler *compiler,
                                 const NanoSol_Token *name) {
  for (size_t i = 0;
       i < sizeof(EXPRESSION_BUILTINS) / sizeof(EXPRESSION_BUILTINS[0]); ++i) {
    if (compiler_identifier_equals(compiler, name,
                                   EXPRESSION_BUILTINS[i].name)) {
      return &EXPRESSION_BUILTINS[i];
    }
  }
  return nullptr;
}

bool compiler_emit_reverse_argument_order(NanoSol_Compiler *compiler,
                                          size_t arity) {
  // Expressions push args left-to-right; many EVM opcodes pop right-to-left.
  if (arity <= 1U) {
    return true;
  }
  if (arity == 2U) {
    return compiler_emit_opcode(compiler, OPCODE_SWAP1);
  }
  if (arity == 3U) {
    return compiler_emit_opcode(compiler, OPCODE_SWAP2);
  }
  if (arity == 4U) {
    return compiler_emit_opcode(compiler, OPCODE_SWAP3) &&
           compiler_emit_opcode(compiler, OPCODE_SWAP1) &&
           compiler_emit_opcode(compiler, OPCODE_SWAP2) &&
           compiler_emit_opcode(compiler, OPCODE_SWAP1);
  }
  compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL, &compiler->current,
                     "unsupported builtin arity");
  return false;
}

bool compiler_parse_call_arguments(NanoSol_Compiler *compiler,
                                   size_t *out_argument_count) {
  size_t argument_count = 0;
  // Leaves evaluated argument values on stack in source order.
  if (compiler->current.kind != TOKEN_RPAREN) {
    while (true) {
      if (!compiler_parse_expression(compiler)) {
        return false;
      }
      argument_count += 1U;
      if (!compiler_match(compiler, TOKEN_COMMA)) {
        break;
      }
    }
  }
  if (!compiler_expect(compiler, TOKEN_RPAREN,
                       "expected ')' after arguments")) {
    return false;
  }
  *out_argument_count = argument_count;
  return true;
}

static int compiler_numeric_digit_value(char c, int base) {
  int digit = -1;
  if (c >= '0' && c <= '9') {
    digit = c - '0';
  } else if (c >= 'a' && c <= 'f') {
    digit = 10 + (c - 'a');
  } else if (c >= 'A' && c <= 'F') {
    digit = 10 + (c - 'A');
  }
  if (digit < 0 || digit >= base) {
    return -1;
  }
  return digit;
}

bool compiler_emit_push_numeric_literal(NanoSol_Compiler *compiler,
                                        const NanoSol_Token *token) {
  uint8_t value[32] = {0};
  size_t begin = token->start;
  size_t end = token->start + token->length;
  int base = 10;

  if (begin + 1U < end && compiler->source[begin] == '0' &&
      (compiler->source[begin + 1U] == 'x' ||
       compiler->source[begin + 1U] == 'X')) {
    base = 16;
    begin += 2U;
  }

  bool any_digit = false;
  // Parse as base-N big integer via repeated multiply-add in a 256-bit buffer.
  for (size_t i = begin; i < end; ++i) {
    char c = compiler->source[i];
    if (c == '_') {
      continue;
    }

    int digit = compiler_numeric_digit_value(c, base);
    if (digit < 0) {
      compiler_set_error(compiler, NANOSOL_ERR_PARSE, token,
                         "invalid numeric literal");
      return false;
    }
    any_digit = true;

    unsigned int carry = (unsigned int)digit;
    for (size_t byte_index = 32; byte_index > 0; --byte_index) {
      unsigned int accum =
          (unsigned int)value[byte_index - 1U] * (unsigned int)base + carry;
      value[byte_index - 1U] = (uint8_t)(accum & 0xffU);
      carry = accum >> 8U;
    }
    if (carry != 0U) {
      compiler_set_error(compiler, NANOSOL_ERR_PARSE, token,
                         "numeric literal exceeds uint256 range");
      return false;
    }
  }

  if (!any_digit) {
    compiler_set_error(compiler, NANOSOL_ERR_PARSE, token,
                       "invalid numeric literal");
    return false;
  }

  size_t first_non_zero = 0;
  while (first_non_zero < 32 && value[first_non_zero] == 0U) {
    first_non_zero += 1U;
  }
  if (first_non_zero == 32U) {
    return compiler_emit_opcode(compiler, OPCODE_PUSH0);
  }

  size_t byte_count = 32U - first_non_zero;
  if (!compiler_emit_opcode(compiler,
                            (uint8_t)(OPCODE_PUSH1 + byte_count - 1U))) {
    return false;
  }
  for (size_t i = first_non_zero; i < 32; ++i) {
    if (!compiler_emit_byte(compiler, value[i])) {
      return false;
    }
  }
  return true;
}

bool compiler_emit_user_function_call(NanoSol_Compiler *compiler,
                                      const NanoSol_Token *call_name,
                                      size_t function_index,
                                      size_t argument_count,
                                      bool discard_result) {
  if (function_index >= compiler->functions_count) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL, call_name,
                       "invalid function id");
    return false;
  }

  size_t parameter_count = compiler->functions[function_index].parameter_count;
  if (argument_count != parameter_count) {
    compiler_set_error(compiler, NANOSOL_ERR_SEMANTIC, call_name,
                       "function expects %zu argument(s), got %zu",
                       parameter_count, argument_count);
    return false;
  }

  if (!compiler_emit_allocate_call_frame(compiler)) {
    return false;
  }

  // Stack top holds the last argument; store right-to-left into slot 0..N-1.
  for (size_t i = argument_count; i > 0; --i) {
    size_t slot_offset = (i - 1U) * LOCAL_SLOT_SIZE;
    if (!compiler_emit_store_current_frame_slot(compiler, slot_offset)) {
      return false;
    }
  }

  // Push synthetic return continuation and jump to callee entry label.
  size_t return_label = compiler_new_label(compiler);
  if (return_label == SIZE_MAX) {
    return false;
  }
  if (!compiler_emit_push_label(compiler, return_label) ||
      !compiler_emit_jump(
          compiler, compiler->functions[function_index].label_index, false) ||
      !compiler_mark_label(compiler, return_label)) {
    return false;
  }

  if (discard_result) {
    return compiler_emit_opcode(compiler, OPCODE_POP);
  }
  return true;
}

bool compiler_emit_internal_function_return(NanoSol_Compiler *compiler) {
  if (compiler->current_function >= compiler->functions_count) {
    compiler_set_error(compiler, NANOSOL_ERR_COMPILE_INTERNAL,
                       &compiler->current, "return outside function");
    return false;
  }

  return compiler_emit_store_current_frame_slot(
             compiler, FUNCTION_RETURN_VALUE_SLOT_OFFSET) &&
         // Load return target + value, tear down frame, then jump back.
         compiler_emit_load_current_frame_slot(
             compiler, FUNCTION_RETURN_ADDRESS_SLOT_OFFSET) &&
         compiler_emit_load_current_frame_slot(
             compiler, FUNCTION_RETURN_VALUE_SLOT_OFFSET) &&
         compiler_emit_release_call_frame(compiler) &&
         compiler_emit_opcode(compiler, OPCODE_SWAP1) &&
         compiler_emit_opcode(compiler, OPCODE_JUMP);
}

bool compiler_emit_external_word_return(NanoSol_Compiler *compiler) {
  // Return the top stack word as ABI memory slice [0, 32).
  return compiler_emit_push_u64(compiler, 0) &&
         compiler_emit_opcode(compiler, OPCODE_MSTORE) &&
         compiler_emit_push_u64(compiler, 32) &&
         compiler_emit_push_u64(compiler, 0) &&
         compiler_emit_opcode(compiler, OPCODE_RETURN);
}
