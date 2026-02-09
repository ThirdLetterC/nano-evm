#ifndef NANOSOL_INTERNAL_H
#define NANOSOL_INTERNAL_H

#include "nanosol.h"

typedef enum {
  TOKEN_EOF = 0,
  TOKEN_INVALID,
  TOKEN_IDENTIFIER,
  TOKEN_NUMBER,
  TOKEN_LBRACE,
  TOKEN_RBRACE,
  TOKEN_LPAREN,
  TOKEN_RPAREN,
  TOKEN_SEMICOLON,
  TOKEN_COMMA,
  TOKEN_ASSIGN,
  TOKEN_PLUS,
  TOKEN_MINUS,
  TOKEN_STAR,
  TOKEN_SLASH,
  TOKEN_PERCENT,
  TOKEN_LT,
  TOKEN_GT,
  TOKEN_LE,
  TOKEN_GE,
  TOKEN_EQEQ,
  TOKEN_NEQ,
  TOKEN_ANDAND,
  TOKEN_OROR,
  TOKEN_BITAND,
  TOKEN_BITOR,
  TOKEN_BITXOR,
  TOKEN_SHL,
  TOKEN_SHR,
  TOKEN_BANG,
  TOKEN_KW_CONTRACT,
  TOKEN_KW_FUNCTION,
  TOKEN_KW_RETURN,
  TOKEN_KW_LET,
  TOKEN_KW_UINT,
  TOKEN_KW_IF,
  TOKEN_KW_ELSE,
  TOKEN_KW_WHILE,
  TOKEN_KW_TRUE,
  TOKEN_KW_FALSE
} NanoSol_TokenKind;

typedef struct {
  NanoSol_TokenKind kind;
  size_t start;
  size_t length;
  size_t line;
  size_t column;
  uint64_t number;
  bool number_overflow;
  bool unterminated_block_comment;
} NanoSol_Token;

typedef struct {
  const char *source;
  size_t source_length;
  size_t position;
  size_t line;
  size_t column;
  bool has_unterminated_block_comment;
  size_t unterminated_comment_line;
  size_t unterminated_comment_column;
} NanoSol_Lexer;

typedef struct {
  uint8_t *bytes;
  size_t size;
  size_t capacity;
} NanoSol_Bytecode;

typedef struct {
  char *name;
  size_t name_length;
  size_t slot_offset;
  size_t scope_depth;
} NanoSol_Local;

typedef struct {
  bool defined;
  size_t address;
} NanoSol_Label;

typedef struct {
  size_t patch_offset;
  size_t label_index;
} NanoSol_Patch;

typedef struct {
  char *name;
  size_t name_length;
  size_t parameter_count;
  size_t label_index;
  bool defined;
} NanoSol_Function;

typedef struct {
  const char *name;
  size_t arity;
  uint8_t opcode;
  bool reverse_arguments;
} NanoSol_BuiltinSpec;

typedef struct {
  const char *source;
  NanoSol_Lexer lexer;
  NanoSol_Token current;
  NanoSol_Status status;
  char *error;
  size_t error_size;
  NanoSol_Bytecode bytecode;
  NanoSol_Local *locals;
  size_t locals_count;
  size_t locals_capacity;
  NanoSol_Label *labels;
  size_t labels_count;
  size_t labels_capacity;
  NanoSol_Patch *patches;
  size_t patches_count;
  size_t patches_capacity;
  NanoSol_Function *functions;
  size_t functions_count;
  size_t functions_capacity;
  size_t current_function;
  size_t entry_function;
  size_t scope_depth;
} NanoSol_Compiler;

static constexpr size_t LOCAL_SLOT_SIZE = 32;
static constexpr size_t JUMP_LABEL_IMMEDIATE_BYTES = 4;
static constexpr size_t FUNCTION_FRAME_SIZE = 1'024;
static constexpr size_t FUNCTION_MAX_LOCAL_SLOTS =
    (FUNCTION_FRAME_SIZE / LOCAL_SLOT_SIZE) - 2U;
static constexpr size_t FUNCTION_RETURN_ADDRESS_SLOT_OFFSET =
    FUNCTION_FRAME_SIZE - (2U * LOCAL_SLOT_SIZE);
static constexpr size_t FUNCTION_RETURN_VALUE_SLOT_OFFSET =
    FUNCTION_FRAME_SIZE - LOCAL_SLOT_SIZE;
static constexpr size_t FRAME_POINTER_SLOT_OFFSET = 0x100;

#endif
