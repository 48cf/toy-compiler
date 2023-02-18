#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <linux/limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

#define ASSERT(x, ...) do { if (!(x)) { fprintf(stderr, __VA_ARGS__); exit(1); } } while (0)
#define ALIGN_UP(x, y) (((x) + ((y) - 1)) & ~((y) - 1))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define LOAD_ADDR 0x400000
#define DATA_ADDR (LOAD_ADDR + 0x1000)

enum {
  TOK_EOF,
  TOK_IDENT,
  TOK_INT,
  TOK_STR,

  TOK_PLUS,
  TOK_MINUS,
  TOK_STAR,
  TOK_SLASH,
  TOK_PERC,
  TOK_LPAREN,
  TOK_LCURLY,
  TOK_RPAREN,
  TOK_RCURLY,
  TOK_LSQUARE,
  TOK_RSQUARE,
  TOK_COMMA,
  TOK_DOT,
  TOK_3DOTS,
  TOK_LT,
  TOK_LTE,
  TOK_LSHIFT,
  TOK_GT,
  TOK_GTE,
  TOK_RSHIFT,
  TOK_EQ,
  TOK_ASSIGN,
  TOK_NEQ,
  TOK_BANG,
  TOK_AMPERSAND,

  TOK_KW_ELSE,
  TOK_KW_FN,
  TOK_KW_IF,
  TOK_KW_IMPORT,
  TOK_KW_RET,
  TOK_KW_WHILE,
  TOK_KW_VAR,
  TOK_KW_VOID,
};

enum {
  IDENT_NONE,
  IDENT_FUNC,
  IDENT_BUILTIN,
  IDENT_SCOPE,
  IDENT_VAR,
  IDENT_GLOBAL,
  IDENT_BUFFER,

  IDENT_MODULE,
  IDENT_PARSING,
};

enum {
  FUNC_NORET = 1 << 0,
  FUNC_HASLOCALS = 1 << 1,
  FUNC_VARARG = 1 << 2,
};

struct identifier {
  int type;
  char *ident;
  union {
    void *value;
    struct {
      uint32_t offset;
      uint16_t flags;
      uint8_t arity;
      uint8_t returns;
    } func;
    struct {
      uint32_t offset;
      uint16_t size;
    } global;
    struct scope *scope;
    int stack_slot;
  };
  struct identifier *next;
};

struct scope {
  struct identifier *first_ident;
};

union token {
  uint64_t int_value;
  struct identifier *ident;
  char *str_value;
};

typedef char *(*builtin_handler_t)(char *, struct scope *, int *, int *);

static int output_file = -1;
static union token token_value;
static struct scope builtin_scope;
static struct scope modules_scope;
static struct identifier *current_func;

static void *emit_text_buffer;
static void *emit_data_buffer;

static size_t emitted_text_length;
static size_t emitted_data_length;

static size_t emit_text(void *data, size_t length) {
  size_t result = emitted_text_length;
  memcpy(emit_text_buffer + emitted_text_length, data, length);
  emitted_text_length += length;
  return result;
}

static size_t emit_data(void *data, size_t length) {
  size_t result = emitted_data_length;
  memcpy(emit_data_buffer + emitted_data_length, data, length);
  emitted_data_length += length;
  return result;
}

static size_t emit_data_bytes(uint8_t value, size_t count) {
  size_t result = emitted_data_length;
  memset(emit_data_buffer + emitted_data_length, value, count);
  emitted_data_length += count;
  return result;
}

#define EMIT(x) static size_t emit##x(uint##x##_t value) { return emit_text(&value, sizeof(value)); }

EMIT(8)
EMIT(16)
EMIT(32)
EMIT(64)

#undef EMIT

static struct identifier *lookup_ident(struct scope *scope, char *name, size_t length, int create) {
  struct identifier *ident = NULL;
  for (struct identifier *it = scope->first_ident; it != NULL; it = it->next) {
    if (it->ident != NULL && !strncmp(name, it->ident, length) && it->ident[length] == '\0') {
      ident = it;
      break;
    }
  }

  if (ident == NULL && create) {
    ident = calloc(1, sizeof(struct identifier));
    ident->ident = strndup(name, length);
    ident->next = scope->first_ident;
    scope->first_ident = ident;
  }
  return ident;
}

static int is_ident_char(char ch) {
  switch (ch) {
    case '0' ... '9':
    case 'a' ... 'z':
    case 'A' ... 'Z':
    case '$':
    case '_':
      return 1;
    default:
      return 0;
  }
}

static int get_digit(char ch) {
  switch (ch) {
    case '0' ... '9': return ch - '0';
    case 'a' ... 'f': return 0xa + (ch - 'a');
    case 'A' ... 'F': return 0xA + (ch - 'A');
    default: return 0xFFFF;
  }
}

static void skip_whitespace(char **data) {
  for (;;) {
    switch (**data) {
      default:
        return;
      case ' ':
      case '\t':
      case '\n':
        (*data)++;
    }
  }
}

static int get_escaped_char(char **data_ptr) {
  char *data = *data_ptr;
  if (*data == 'x') {
    int escaped_hex = 0;
    for (int i = 0; i < 2; i++) {
      ASSERT(data[i + 1] != '\0', "Found an EOF while parsing a hex escape\n");
      escaped_hex *= 16;
      escaped_hex += get_digit(data[i + 1]);
    }
    *data_ptr += 3;
    return escaped_hex;
  } else if (*data == 't') {
    *data_ptr += 1;
    return '\t';
  } else if (*data == 'n') {
    *data_ptr += 1;
    return '\n';
  } else if (*data == 'e') {
    *data_ptr += 1;
    return '\e';
  } else if (*data == '0') {
    *data_ptr += 1;
    return '\0';
  } else if (*data == '\\') {
    *data_ptr += 1;
    return '\\';
  } else if (*data == '\'') {
    *data_ptr += 1;
    return '\'';
  } else if (*data == '"') {
    *data_ptr += 1;
    return '"';
  }

  ASSERT(0, "Found an invalid escape '\\%c'\n", *data);
}

static int get_token(char **data_ptr, int *length, struct scope *scope) {
#define IS_KW(x, y) do { if (!strncmp(start, x, sizeof(x) - 1) && !is_ident_char(start[sizeof(x) - 1])) return y; } while (0)
#define CHAR_TOKEN(x) do { *length = 1; return x; } while (0)
#define STR_TOKEN(x, y) do { if (!strncmp(data, x, sizeof(x) - 1)) { *length = sizeof(x) - 1; return y; } } while (0)

start:;
  *length = 0;
  skip_whitespace(data_ptr);
  char *data = *data_ptr;
  int base = 10;

  switch (*data) {
    case '\0':
      return TOK_EOF;
    case '+': CHAR_TOKEN(TOK_PLUS);
    case '-': CHAR_TOKEN(TOK_MINUS);
    case '*': CHAR_TOKEN(TOK_STAR);
    case '/':
      if (*(data + 1) == '/') {
        while (*data != '\n' && *data != '\0') {
          data++;
        }
        *data_ptr = data;
        goto start;
      }
      CHAR_TOKEN(TOK_SLASH);
    case '%': CHAR_TOKEN(TOK_PERC);
    case '(': CHAR_TOKEN(TOK_LPAREN);
    case '{': CHAR_TOKEN(TOK_LCURLY);
    case ')': CHAR_TOKEN(TOK_RPAREN);
    case '}': CHAR_TOKEN(TOK_RCURLY);
    case '[': CHAR_TOKEN(TOK_LSQUARE);
    case ']': CHAR_TOKEN(TOK_RSQUARE);
    case ',': CHAR_TOKEN(TOK_COMMA);
    case '.':
      STR_TOKEN("...", TOK_3DOTS);
      CHAR_TOKEN(TOK_DOT);
    case '&': CHAR_TOKEN(TOK_AMPERSAND);
    case '<':
      STR_TOKEN("<=", TOK_LTE);
      STR_TOKEN("<<", TOK_LSHIFT);
      CHAR_TOKEN(TOK_LT);
    case '>':
      STR_TOKEN(">=", TOK_GTE);
      STR_TOKEN(">>", TOK_RSHIFT);
      CHAR_TOKEN(TOK_GT);
    case '=':
      STR_TOKEN("==", TOK_EQ);
      CHAR_TOKEN(TOK_ASSIGN);
    case '!':
      STR_TOKEN("!=", TOK_NEQ);
      CHAR_TOKEN(TOK_BANG);
    case 'a' ... 'z':
    case 'A' ... 'Z':
    case '$':
    case '_': {
      char *start = data;
      while (is_ident_char(*data)) {
        data++;
      }

      int ident_length = data - start;
      *length = ident_length;

      IS_KW("else", TOK_KW_ELSE);
      IS_KW("fn", TOK_KW_FN);
      IS_KW("if", TOK_KW_IF);
      IS_KW("import", TOK_KW_IMPORT);
      IS_KW("ret", TOK_KW_RET);
      IS_KW("while", TOK_KW_WHILE);
      IS_KW("var", TOK_KW_VAR);
      IS_KW("void", TOK_KW_VOID);

      struct identifier *ident = lookup_ident(scope, start, ident_length, 1);
      token_value.ident = ident;
      return TOK_IDENT;
    }
    case '0':
      switch (data[1]) {
        case 'b': base = 2; data += 2; *length = 2; break;
        case 'o': base = 8; data += 2; *length = 2; break;
        case 'x': base = 16; data += 2; *length = 2; break;
      }
      // fallthrough
    case '1' ... '9': {
      token_value = (union token){.int_value = 0};
      char *start = data;
      int digit;
      while ((digit = get_digit(*data)) < base) {
        data++;
        token_value.int_value *= base;
        token_value.int_value += digit;
      }
      *length += data - start;
      return TOK_INT;
    }
    case '\'': {
      char *start = data++;
      if (*data == '\\') {
        data++;
        token_value.int_value = get_escaped_char(&data);
      } else if (*data == '\n') {
        fprintf(stderr, "Found a new line in the middle of a character literal\n");
        exit(1);
      } else if (*data == '\0') {
        fprintf(stderr, "Found an EOF while parsing the character literal\n");
        exit(1);
      } else {
        token_value.int_value = *data;
        data++;
      }
      data++; // Skip over the closing quote
      *length = data - start;
      return TOK_INT;
    }
    case '"': {
      int escaped = 0, str_length = 0, capacity = 32;
      char *start = data++;
      char *result = calloc(capacity, 1);
      for (; *data != '"' || escaped; data++) {
        if (str_length == capacity - 1) {
          capacity *= 2;
          result = reallocarray(result, capacity, 1);
        }

        if (!escaped) {
          if (*data == '\\') {
            escaped = 1;
          } else if (*data == '\n') {
            fprintf(stderr, "Found a new line in the middle of a string\n");
            exit(1);
          } else if (*data == '\0') {
            fprintf(stderr, "Found an EOF while parsing the string\n");
            exit(1);
          } else {
            result[str_length++] = *data;
          }
        } else {
          result[str_length++] = get_escaped_char(&data);
          escaped = 0;
          data--;
        }
      }
      result[str_length] = '\0';
      data++; // Skip over the closing quote
      int ident_length = data - start;
      *length = ident_length;
      token_value.str_value = result;
      return TOK_STR;
    }
  }

#undef IS_KW
#undef CHAR_TOKEN
#undef STR_TOKEN

  ASSERT(0, "Unrecognized input character: '%.1s'\n", data);
}

static const char *token_name(int token) {
  switch (token) {
    case TOK_EOF: return "TOK_EOF";
    case TOK_IDENT: return "TOK_IDENT";
    case TOK_INT: return "TOK_INT";
    case TOK_STR: return "TOK_STR";

    case TOK_PLUS: return "TOK_PLUS";
    case TOK_MINUS: return "TOK_MINUS";
    case TOK_STAR: return "TOK_STAR";
    case TOK_SLASH: return "TOK_SLASH";
    case TOK_PERC: return "TOK_PERC";
    case TOK_LPAREN: return "TOK_LPAREN";
    case TOK_LCURLY: return "TOK_LCURLY";
    case TOK_RPAREN: return "TOK_RPAREN";
    case TOK_RCURLY: return "TOK_RCURLY";
    case TOK_LSQUARE: return "TOK_LSQUARE";
    case TOK_RSQUARE: return "TOK_RSQUARE";
    case TOK_COMMA: return "TOK_COMMA";
    case TOK_DOT: return "TOK_DOT";
    case TOK_3DOTS: return "TOK_3DOTS";
    case TOK_LT: return "TOK_LT";
    case TOK_LTE: return "TOK_LTE";
    case TOK_LSHIFT: return "TOK_LSHIFT";
    case TOK_GT: return "TOK_GT";
    case TOK_GTE: return "TOK_GTE";
    case TOK_RSHIFT: return "TOK_RSHIFT";
    case TOK_EQ: return "TOK_EQ";
    case TOK_ASSIGN: return "TOK_ASSIGN";
    case TOK_NEQ: return "TOK_NEQ";
    case TOK_BANG: return "TOK_BANG";
    case TOK_AMPERSAND: return "TOK_AMPERSAND";

    case TOK_KW_ELSE: return "TOK_KW_ELSE";
    case TOK_KW_FN: return "TOK_KW_FN";
    case TOK_KW_IF: return "TOK_KW_IF";
    case TOK_KW_IMPORT: return "TOK_KW_IMPORT";
    case TOK_KW_RET: return "TOK_KW_RET";
    case TOK_KW_WHILE: return "TOK_KW_WHILE";
    case TOK_KW_VAR: return "TOK_KW_VAR";
    case TOK_KW_VOID: return "TOK_KW_VOID";

    default: return "???";
  }
}

#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7

#define REX_B 0x41
#define REX_W 0x48

#define CC_NOT 0x1
#define CC_BELOW 0x2
#define CC_ZERO 0x4
#define CC_BELOW_EQ 0x6

#define EMIT_FN(name, body) static size_t name { size_t EMIT_FN_result = emitted_text_length; body return EMIT_FN_result; }

EMIT_FN(emit_modrm(uint8_t mod, uint8_t reg, uint8_t rm), {
  emit8(mod << 6 | reg << 3 | rm);
})

EMIT_FN(add_reg_imm(uint8_t reg, int32_t imm), {
  emit8(REX_W);
  emit8(0x81);
  emit_modrm(0b11, 0, reg);
  emit32(imm);
})

EMIT_FN(sub_reg_imm(uint8_t reg, int32_t imm), {
  emit8(REX_W);
  emit8(0x81);
  emit_modrm(0b11, 5, reg);
  emit32(imm);
})

EMIT_FN(push_reg(uint8_t reg), {
  if (reg >= 8) {
    emit8(REX_B);
  }
  emit8(0x50 | (reg & 0x7));
})

EMIT_FN(pop_reg(uint8_t reg), {
  if (reg >= 8) {
    emit8(REX_B);
  }
  emit8(0x58 | (reg & 0x7));
})

EMIT_FN(movabs(uint8_t to, uint64_t value), {
  emit8(REX_W);
  emit8(0xB8 | to);
  emit64(value);
})

EMIT_FN(mov_reg_reg(uint8_t to, uint8_t from), {
  emit8(REX_W);
  emit8(0x8B);
  emit_modrm(0b11, to, from);
})

EMIT_FN(test_reg_reg(uint8_t ra, uint8_t rb), {
  emit8(REX_W);
  emit8(0x85);
  emit_modrm(0b11, rb, ra);
})

EMIT_FN(cmp_reg_reg(uint8_t ra, uint8_t rb), {
  emit8(REX_W);
  emit8(0x39);
  emit_modrm(0b11, rb, ra);
})

EMIT_FN(jump_cc(uint8_t cc, int32_t disp), {
  emit8(0x0F);
  emit8(0x80 | cc);
  emit32(disp);
})

EMIT_FN(set_cc(uint8_t cc, uint8_t reg), {
  emit8(0x0F);
  emit8(0x90 | cc);
  emit_modrm(0b11, 0, reg);
})

static void patch_imm32(size_t from, size_t to, size_t length) {
  size_t imm_offset = from + length - 4;
  *(int32_t*)(emit_text_buffer + imm_offset) = to - (from + length);
}

#undef EMIT_FN

#define PEEK ({ int PEEK_length; get_token(&data, &PEEK_length, scope); })
#define ADVANCE ({ union token ADVANCE_token = token_value; token = get_token(&data, &length, scope); data += length; ADVANCE_token; })
#define MATCHES(x) (PEEK == x)
#define EXPECT(x, msg) ({ ASSERT(MATCHES(x), msg ", found %s\n", token_name(PEEK)); ADVANCE; })

static uint8_t vararg_reg = 12;
static uint8_t syscall_regs[] = {RAX, RDI, RSI, RDX, 10, 8, 9};
static uint8_t return_regs[] = {RAX, RBX, RDX, RDI, RSI};

static char *parse_expression(char *data, struct scope *scope, int *stack_values, int *does_return, int expected_values);
static char *parse_block(char *data, struct scope *scope, int local_count, int *does_return);

static char *parse_varargs(char *data, struct scope *scope, int *stack_values, int *does_return) {
  int token, length, vararg_stack_values = 0;
  EXPECT(TOK_LSQUARE, "Expected opening square bracket before varargs");
  while (!MATCHES(TOK_RSQUARE)) {
    data = parse_expression(data, scope, &vararg_stack_values, does_return, -1);
  }
  EXPECT(TOK_RSQUARE, "Expected closing square bracket after varargs");
  // push imm8
  emit8(0x6A);
  emit8(vararg_stack_values);
  // pop r12
  emit8(0x41);
  emit8(0x5C);
  return data;
}

static char *parse_ident_expr(char *data, struct scope *scope, struct identifier *ident, int *stack_values, int *does_return) {
  int token, length;
  switch (ident->type) {
    case IDENT_NONE:
      ASSERT(0, "Use of undefined identifier '%s'\n", ident->ident);
    case IDENT_FUNC: {
      data = parse_expression(data, scope, stack_values, does_return, ident->func.arity);
      if (ident->func.flags & FUNC_VARARG) {
        data = parse_varargs(data, scope, stack_values, does_return);
      }
      size_t call_addr = emitted_text_length;
      emit8(0xE8);
      emit32(ident->func.offset - (call_addr + 5));
      *stack_values -= ident->func.arity;
      *stack_values += ident->func.returns;
      if (ident->func.flags & FUNC_NORET) {
        *does_return = 0;
      } else {
        if (ident->func.flags & FUNC_VARARG) {
          // lea rsp, [rsp + r12 * 8]
          emit_text("\x4A\x8D\x24\xE4", 4);
        }
        if (ident->func.arity > 0) {
          add_reg_imm(RSP, ident->func.arity * 8);
        }
        for (int i = 0; i < ident->func.returns; i++) {
          push_reg(return_regs[i]);
        }
      }
      break;
    }
    case IDENT_BUILTIN:
      return ((builtin_handler_t)ident->value)(data, scope, stack_values, does_return);
    case IDENT_SCOPE:
      EXPECT(TOK_DOT, "Expected a '.' after scope name");
      union token member = EXPECT(TOK_IDENT, "Expected an identifier");
      struct identifier *member_ident = lookup_ident(ident->scope, member.ident->ident, strlen(member.ident->ident), 0);
      if (member_ident == NULL) {
        ASSERT(0, "Use of undefined identifier '%s' in scope '%s'\n", member.ident->ident, ident->ident);
      }
      return parse_ident_expr(data, scope, member_ident, stack_values, does_return);
    case IDENT_VAR:
      // push r/m64
      if (current_func->func.flags & FUNC_VARARG && ident->stack_slot > 0) {
        emit_text("\x42\xFF\xB4\xE5", 4);
        emit32(ident->stack_slot * 8);
      } else {
        emit8(0xFF);
        emit_modrm(0b10, 6, RBP);
        emit32(ident->stack_slot * 8);
      }
      *stack_values += 1;
      break;
    case IDENT_GLOBAL:
      // movabs rax, [imm64]
      emit8(REX_W);
      emit8(0xA1);
      emit64(ident->global.offset);
      push_reg(RAX);
      *stack_values += 1;
      break;
    case IDENT_BUFFER:
      movabs(RAX, ident->global.offset);
      push_reg(RAX);
      *stack_values += 1;
      break;
    default:
      ASSERT(0, "ident->type == %d\n", ident->type);
  }
  return data;
}

static char *parse_expression(char *data, struct scope *scope, int *stack_values, int *does_return, int expected_values) {
  *does_return = 1;

  int first = expected_values < 0, new_stack_values = 0;
  while (first || new_stack_values < expected_values) {
    first = 0;

    int token, length;
    uint8_t cc;

    switch (PEEK) {
      case TOK_IDENT: {
        union token ident = ADVANCE;
        data = parse_ident_expr(data, scope, ident.ident, &new_stack_values, does_return);
        break;
      }
      case TOK_INT: {
        union token int_tok = ADVANCE;
        if (int_tok.int_value < 0x80 || int_tok.int_value > 0xFFFFFFFFFFFFFF7F) {
          // push imm8
          emit8(0x6A);
          emit8(int_tok.int_value);
        } else if (int_tok.int_value < 0x80000000 || int_tok.int_value > 0xFFFFFFFF7FFFFFFF) {
          // push imm32
          emit8(0x68);
          emit32(int_tok.int_value);
        } else {
          movabs(RAX, int_tok.int_value);
          push_reg(RAX);
        }
        new_stack_values += 1;
        break;
      }
      case TOK_STR: {
        union token str_tok = ADVANCE;
        size_t ptr = emit_data(str_tok.str_value, strlen(str_tok.str_value) + 1);
        movabs(RAX, ptr + DATA_ADDR);
        push_reg(RAX);
        new_stack_values += 1;
        break;
      }
      case TOK_ASSIGN: {
        ADVANCE;
        union token target = EXPECT(TOK_IDENT, "Expected an identifier");
        data = parse_expression(data, scope, &new_stack_values, does_return, 1);
        switch (target.ident->type) {
          case IDENT_VAR:
            if (current_func->func.flags & FUNC_VARARG && target.ident->stack_slot > 0) {
              // pop [rbp + r12 * 8 + disp32]
              emit_text("\x42\x8F\x84\xE5", 4);
              emit32(target.ident->stack_slot * 8);
            } else {
              // pop [rbp disp32]
              emit8(0x8F);
              emit_modrm(0b10, 0, RBP);
              emit32(target.ident->stack_slot * 8);
            }
            break;
          case IDENT_GLOBAL:
            // movabs rax, imm64
            movabs(RAX, target.ident->global.offset);
            // pop [rax]
            emit8(0x8F);
            emit8(0x00);
            break;
          default:
            ASSERT(0, "Expected a local or global variable, found %d\n", target.ident->type);
        }
        new_stack_values -= 1;
        break;
      }
      if (0) { case TOK_LT: cc = CC_BELOW; }
      if (0) { case TOK_LTE: cc = CC_BELOW_EQ; }
      if (0) { case TOK_GT: cc = CC_NOT | CC_BELOW_EQ; }
      if (0) { case TOK_GTE: cc = CC_NOT | CC_BELOW; }
      if (0) { case TOK_EQ: cc = CC_ZERO; }
      if (0) { case TOK_NEQ: cc = CC_NOT | CC_ZERO; }
        ADVANCE;
        data = parse_expression(data, scope, &new_stack_values, does_return, 2);
        pop_reg(RBX); // rhs
        pop_reg(RAX); // lhs
        cmp_reg_reg(RAX, RBX);
        set_cc(cc, RAX);
        // movzx r64, r/m8
        emit8(REX_W);
        emit8(0x0F);
        emit8(0xB6);
        emit_modrm(0b11, RAX, RAX);
        push_reg(RAX);
        new_stack_values -= 1;
        break;
      case TOK_PLUS:
      case TOK_MINUS: {
        ADVANCE;
        data = parse_expression(data, scope, &new_stack_values, does_return, 2);
        pop_reg(RBX); // rhs
        pop_reg(RAX); // lhs
        switch (token) {
          case TOK_PLUS:
            // add r64, r/m64
            emit8(0x48);
            emit8(0x01);
            emit8(0xD8);
            break;
          case TOK_MINUS:
            // sub r64, r/m64
            emit8(0x48);
            emit8(0x29);
            emit8(0xD8);
            break;
        }
        push_reg(RAX);
        new_stack_values -= 1;
        break;
      }
      case TOK_STAR: {
        ADVANCE;
        data = parse_expression(data, scope, &new_stack_values, does_return, 2);
        pop_reg(RAX);
        emit_text("\x48\xF7\x24\x24", 4); // mul qword ptr [rsp]
        emit_text("\x48\x89\x04\x24", 4); // mov qword ptr [rsp], rax
        new_stack_values -= 1;
        break;
      };
      case TOK_SLASH:
      case TOK_PERC:
        ADVANCE;
        data = parse_expression(data, scope, &new_stack_values, does_return, 2);
        // xor rdx, rdx
        emit_text("\x48\x31\xD2", 3);
        pop_reg(RBX); // rhs
        pop_reg(RAX); // lhs
        // div rbx
        emit_text("\x48\xF7\xF3", 3);
        switch (token) {
          case TOK_SLASH:
            push_reg(RAX);
            break;
          case TOK_PERC:
            push_reg(RDX);
            break;
        }
        new_stack_values -= 1;
        break;
      case TOK_LPAREN: {
        ADVANCE;
        int paren_stack_values = 0;
        data = parse_expression(data, scope, &paren_stack_values, does_return, 1);
        ASSERT(paren_stack_values == 1, "Parenthesized expression may only result in one stack value, found %d", paren_stack_values);
        new_stack_values += paren_stack_values;
        EXPECT(TOK_RPAREN, "Expected a closing parenthesis");
        break;
      }
      default:
        ASSERT(0, "Expected an expression, got %s (expected %d values, got %d)\n", token_name(PEEK), expected_values, new_stack_values);
    }
  }
  *stack_values += new_stack_values;
  return data;
}

static char *parse_if_statement(char *data, struct scope *scope, int local_count, int *does_return) {
  int token, length, stack_values = 0;
  data = parse_expression(data, scope, &stack_values, does_return, 1);
  ASSERT(stack_values == 1, "Expected only a single stack value, found %d\n", stack_values);
  ASSERT(*does_return == 1, "If condition must be a returning value\n");
  pop_reg(RAX);
  test_reg_reg(RAX, RAX);
  size_t if_jump = jump_cc(CC_ZERO, 0);
  data = parse_block(data, scope, local_count, does_return);
  for (int first = 1;;) {
    size_t else_jump;
    if (MATCHES(TOK_KW_ELSE)) {
      else_jump = emit8(0xE9);
      emit32(0);
    }
    if (first) {
      patch_imm32(if_jump, emitted_text_length, 6);
      first = 0;
    }
    if (MATCHES(TOK_KW_ELSE)) {
      ADVANCE;
      int branch_returns;
      if (MATCHES(TOK_LCURLY)) {
        data = parse_block(data, scope, local_count, &branch_returns);
        *does_return |= branch_returns;
      } else if (MATCHES(TOK_KW_IF)) {
        ADVANCE;
        data = parse_if_statement(data, scope, local_count, &branch_returns);
      } else {
        ASSERT(0, "Expected a block or if statement after `else`, found %s\n", token_name(PEEK));
      }
      patch_imm32(else_jump, emitted_text_length, 5);
    } else {
      break;
    }
  }
  return data;
}

static char *parse_block(char *data, struct scope *scope, int local_count, int *does_return) {
  *does_return = 1;

  int token, length;
  EXPECT(TOK_LCURLY, "Expected function body after argument list");
  while (!MATCHES(TOK_RCURLY)) {
    switch (PEEK) {
      case TOK_KW_IF: {
        ADVANCE;
        data = parse_if_statement(data, scope, local_count, does_return);
        break;
      }
      case TOK_KW_WHILE: {
        ADVANCE;
        size_t start = emitted_text_length;
        int stack_values = 0;
        data = parse_expression(data, scope, &stack_values, does_return, 1);
        ASSERT(stack_values == 1, "Expected only a single stack value, found %d\n", stack_values);
        ASSERT(*does_return == 1, "If condition must be a returning value\n");
        pop_reg(RAX);
        test_reg_reg(RAX, RAX);
        size_t cond_jump = jump_cc(CC_ZERO, 0);
        data = parse_block(data, scope, local_count, does_return);
        size_t jmp_back = emit8(0xE9); emit32(0);
        patch_imm32(jmp_back, start, 5);
        patch_imm32(cond_jump, emitted_text_length, 6);
        break;
      }
      case TOK_KW_RET: {
        ADVANCE;
        int stack_values = 0;
        data = parse_expression(data, scope, &stack_values, does_return, current_func->func.returns);
        ASSERT(stack_values == current_func->func.returns, "Too many values to return: expected %d, got %d\n", current_func->func.returns, stack_values);
        for (int i = 0; i < current_func->func.returns; i++) {
          pop_reg(return_regs[stack_values - i - 1]);
        }
        if (local_count > 0) {
          add_reg_imm(RSP, local_count * 8);
        }
        pop_reg(RBP);
        emit8(0xC3); // ret
        current_func->func.flags &= ~FUNC_NORET;
        break;
      }
      default: {
        int stack_values = 0;
        data = parse_expression(data, scope, &stack_values, does_return, -1);
        if (stack_values > 0) {
          add_reg_imm(RSP, stack_values * 8);
        }
        break;
      }
    }
  }
  EXPECT(TOK_RCURLY, "Expected a closing curly after function body");
  return data;
}

static struct scope *parse_file(char *path) {
  char *dirpath = dirname(strdup(path));

  struct scope *scope = calloc(1, sizeof(struct scope));
  scope->first_ident = builtin_scope.first_ident;

  struct identifier *module = lookup_ident(&modules_scope, path, strlen(path), 1);
  if (module->type == IDENT_NONE) {
    module->type = IDENT_PARSING;
    module->scope = scope;
  } else {
    return module->scope;
  }

  int file = openat(AT_FDCWD, path, O_RDONLY);
  ASSERT(file > 0, "Failed to open input file %s: %s\n", path, strerror(errno));

  int file_size = lseek(file, 0, SEEK_END);
  char *data = mmap(NULL, file_size + 0xFFF, PROT_READ, MAP_SHARED, file, 0);
  ASSERT(data != MAP_FAILED, "Failed to memory map input file: %s\n", strerror(errno));

  int token, length;
  for (;;) {
    ADVANCE;

    switch (token) {
      case TOK_EOF:
        module->type = IDENT_MODULE;
        return scope;
      case TOK_KW_IMPORT: {
        union token import_file = EXPECT(TOK_STR, "Expected a file name to import");
        union token import_scope = EXPECT(TOK_IDENT, "Expected a scope name for imported file");
        char *import_path = import_file.str_value;
        if (import_file.str_value[0] != '/') {
          if (!strncmp(import_file.str_value, "./", 2)) {
            import_path = import_file.str_value + 2;
          }
          char *result = calloc(strlen(dirpath) + strlen(import_path) + 2, 1);
          strcat(result, dirpath);
          strcat(result, "/");
          strcat(result, import_path);
          import_path = result;
        }
        ASSERT(strlen(import_path) > 0, "Import file path cannot be empty");
        import_scope.ident->type = IDENT_SCOPE;
        import_scope.ident->scope = parse_file(import_path);
        break;
      }
      case TOK_KW_VAR: {
        union token var_name = EXPECT(TOK_IDENT, "Expected an identifier after keyword 'var'");
        ASSERT(var_name.ident->type == IDENT_NONE, "Global variable '%s' was already defined before\n", var_name.ident->ident);
        if (MATCHES(TOK_LSQUARE)) {
          ADVANCE;
          union token byte_count = EXPECT(TOK_INT, "Expected the buffer size");
          size_t ptr = emit_data_bytes(0, byte_count.int_value);
          var_name.ident->type = IDENT_BUFFER;
          var_name.ident->global.offset = ptr + DATA_ADDR;
          var_name.ident->global.size = byte_count.int_value;
          EXPECT(TOK_RSQUARE, "Expected a closing square bracket after buffer size");
        } else {
          size_t ptr = emit_data_bytes(0, 8);
          var_name.ident->type = IDENT_GLOBAL;
          var_name.ident->global.offset = ptr + DATA_ADDR;
          var_name.ident->global.size = 8;
        }
        break;
      }
      case TOK_KW_FN: {
        union token fn_name = EXPECT(TOK_IDENT, "Expected an identifier after keyword 'fn'");
        ASSERT(fn_name.ident->type == IDENT_NONE, "Function '%s' was already defined before\n", fn_name.ident->ident);
        fn_name.ident->type = IDENT_FUNC;
        fn_name.ident->func.flags |= FUNC_NORET;
        fn_name.ident->func.offset = emitted_text_length;
        current_func = fn_name.ident;
        EXPECT(TOK_LPAREN, "Expected an opening paren after function name");
        while (!MATCHES(TOK_RPAREN)) {
          ASSERT((fn_name.ident->func.flags & FUNC_VARARG) == 0, "Positional arguments must come before varargs");
          if (MATCHES(TOK_3DOTS)) {
            ADVANCE;
            fn_name.ident->func.flags |= FUNC_VARARG;
          } else {
            union token arg_name = EXPECT(TOK_IDENT, "Expected an argument name");
            ASSERT(arg_name.ident->type == IDENT_NONE, "Function argument '%s' was already defined before\n", arg_name.ident->ident);
            arg_name.ident->type = IDENT_VAR;
            fn_name.ident->func.arity++;
          }
          if (!MATCHES(TOK_COMMA)) {
            break;
          }
          ADVANCE;
        }
        EXPECT(TOK_RPAREN, "Expected a closing paren after argument list");
        int stack_offset = 2;
        for (struct identifier *arg = scope->first_ident; arg != NULL && arg->type == IDENT_VAR; arg = arg->next) {
          arg->stack_slot = stack_offset++;
        }
        int local_count = 0;
        if (MATCHES(TOK_LSQUARE)) {
          ADVANCE;
          while (!MATCHES(TOK_RSQUARE)) {
            union token local_name = EXPECT(TOK_IDENT, "Expected local variable name");
            ASSERT(local_name.ident->type == IDENT_NONE, "Local variable '%s' was already defined before\n", local_name.ident->ident);
            local_name.ident->type = IDENT_VAR;
            local_name.ident->stack_slot = -(++local_count);
            if (!MATCHES(TOK_COMMA)) {
              break;
            }
            ADVANCE;
          }
          EXPECT(TOK_RSQUARE, "Expected a closing square after local variable list");
        }
        if (MATCHES(TOK_INT)) {
          union token return_count = ADVANCE;
          fn_name.ident->func.returns = return_count.int_value;
        } else if (MATCHES(TOK_KW_VOID)) {
          ADVANCE;
          fn_name.ident->func.returns = 0;
        } else {
          fn_name.ident->func.returns = 1;
        }
        push_reg(RBP);
        mov_reg_reg(RBP, RSP);
        if (local_count > 0) {
          fn_name.ident->func.flags |= FUNC_HASLOCALS;
          sub_reg_imm(RSP, local_count * 8);
        }
        int does_return;
        data = parse_block(data, scope, local_count, &does_return);
        if (does_return) {
          fn_name.ident->func.flags &= ~FUNC_NORET;
        }
        for (struct identifier *arg = scope->first_ident; arg != NULL && arg->type == IDENT_VAR;) {
          struct identifier *next = arg->next;
          scope->first_ident = next;
          arg = next;
        }
        break;
      }
      default:
        ASSERT(0, "Expected an 'fn' keyword, got %s\n", token_name(token));
    }
  }
}

static char *handle_builtin_unreachable(char *data, struct scope *scope, int *stack_values, int *does_return) {
  *does_return = 0;
  emit_text("\x0F\x0B", 2); // ud2
  return data;
}

static char *handle_builtin_arg(char *data, struct scope *scope, int *stack_values, int *does_return) {
  *does_return = 1;
  int token, length;
  emit_text("\x4C\x89\xE0", 3); // mov rax, r12
  emit_text("\x48\xC1\xE0\x03", 4); // shl rax, 3
  if (MATCHES(TOK_INT)) {
    union token arg_index = EXPECT(TOK_INT, "Expected argument index");
    sub_reg_imm(RAX, (arg_index.int_value - 1) * 8);
    *stack_values += 1;
} else {
    data = parse_expression(data, scope, stack_values, does_return, 1);
    pop_reg(RBX);
    emit_text("\x48\xFF\xCB", 3); // dec rbx
    emit_text("\x48\xC1\xE3\x03", 4); // shl rbx, 3
    emit_text("\x48\x29\xD8", 3); // sub rax, rbx
  }
  emit_text("\xFF\x74\x05\x00", 4); // push [rbp + rax]
  return data;
}

static char *handle_builtin_argc(char *data, struct scope *scope, int *stack_values, int *does_return) {
  *does_return = 1;
  *stack_values += 1;
  // push r12
  emit8(REX_B);
  emit8(0x50 | (12 & 7));
  return data;
}

static char *handle_builtin_entry(char *data, struct scope *scope, int *stack_values, int *does_return) {
  int token, length;
  union token entry = EXPECT(TOK_IDENT, "Expected entry function name");
  ASSERT(entry.ident->func.arity == 3, "Expected entry function to have 3 arguments");
  ASSERT(entry.ident->func.returns == 1, "Expected entry function to return 1 value");
  emit_text("\x48\x8B\x7D\x08", 4); // mov rdi, [rbp + 0x8]
  emit_text("\x48\x8D\x75\x10", 4); // lea rsi, [rbp + 0x10]
  emit_text("\x48\x8D\x54\xFD\x18", 5); // lea rdx, [rbp + rdi * 8 + 0x18]
  push_reg(RDI);
  push_reg(RSI);
  push_reg(RDX);
  size_t call_addr = emitted_text_length;
  emit8(0xE8);
  emit32(entry.ident->func.offset - (call_addr + 5));
  add_reg_imm(RSP, 24);
  push_reg(RAX);
  *stack_values += 1;
  return data;
}

static char *handle_builtin_syscall(char *data, struct scope *scope, int *stack_values, int *does_return) {
  int token, length;
  union token arg_count = EXPECT(TOK_INT, "Expected syscall argument count");
  ASSERT(arg_count.int_value > 0, "Expected at least one syscall argument");
  ASSERT(arg_count.int_value <= sizeof(syscall_regs), "Expected at most 7 syscall arguments");
  data = parse_expression(data, scope, stack_values, does_return, (int)arg_count.int_value);
  for (int i = 0; i < (int)arg_count.int_value; i++) {
    pop_reg(syscall_regs[(int)arg_count.int_value - i - 1]);
  }
  emit8(0x0F);
  emit8(0x05);
  push_reg(RAX);
  *stack_values -= (int)arg_count.int_value;
  *stack_values += 1;
  return data;
}

static char *handle_builtin_sizeof(char *data, struct scope *scope, int *stack_values, int *does_return) {
  int token, length, size;
  union token ident = EXPECT(TOK_IDENT, "Expected an identifier");
  switch (ident.ident->type) {
    case IDENT_VAR:
      size = 8;
      break;
    case IDENT_GLOBAL:
    case IDENT_BUFFER:
      size = ident.ident->global.size;
      break;
    default:
      ASSERT(0, "Can't get a sizeof of identifier '%s' of type %d\n", ident.ident->ident, ident.ident->type);
  }
  // push imm32
  emit8(0x68);
  emit32(size);
  *stack_values += 1;
  return data;
}

static char *handle_builtin_read8(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 1);
  pop_reg(RAX);
  emit_text("\x48\x0f\xb6\x00", 4);
  push_reg(RAX);
  *does_return = 1;
  return data;
}

static char *handle_builtin_read16(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 1);
  pop_reg(RAX);
  emit_text("\x48\x0f\xb7\x00", 4);
  push_reg(RAX);
  *does_return = 1;
  return data;
}

static char *handle_builtin_read32(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 1);
  pop_reg(RAX);
  emit_text("\x8b\x00", 2);
  push_reg(RAX);
  *does_return = 1;
  return data;
}

static char *handle_builtin_read64(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 1);
  pop_reg(RAX);
  emit_text("\x48\x8b\x00", 3);
  push_reg(RAX);
  *does_return = 1;
  return data;
}

static char *handle_builtin_write8(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 2);
  pop_reg(RBX);
  pop_reg(RAX);
  emit_text("\x88\x18", 2);
  *stack_values -= 2;
  *does_return = 1;
  return data;
}

static char *handle_builtin_write16(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 2);
  pop_reg(RBX);
  pop_reg(RAX);
  emit_text("\x66\x89\x18", 3);
  *stack_values -= 2;
  *does_return = 1;
  return data;
}

static char *handle_builtin_write32(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 2);
  pop_reg(RBX);
  pop_reg(RAX);
  emit_text("\x89\x18", 2);
  *stack_values -= 2;
  *does_return = 1;
  return data;
}

static char *handle_builtin_write64(char *data, struct scope *scope, int *stack_values, int *does_return) {
  data = parse_expression(data, scope, stack_values, does_return, 2);
  pop_reg(RBX);
  pop_reg(RAX);
  emit_text("\x48\x89\x18", 3);
  *stack_values -= 2;
  *does_return = 1;
  return data;
}

static void add_builtin(char *name, builtin_handler_t handler) {
  struct identifier *ident = lookup_ident(&builtin_scope, name, strlen(name), 1);
  ASSERT(ident->type == IDENT_NONE, "Tried to override existing identifier with builtin '%s'\n", name);
  ident->type = IDENT_BUILTIN;
  ident->value = handler;
}

struct elf_hdr {
  Elf64_Ehdr header;
  Elf64_Phdr phdr[2];
};

int main(int argc, char **argv) {
  ASSERT(argc >= 0, "Usage: %s <input> <output>\n", argv[0]);

  output_file = openat(AT_FDCWD, argv[2], O_RDWR | O_CREAT | O_TRUNC);
  ASSERT(output_file > 0, "Failed to open output file %s: %s\n", argv[2], strerror(errno));

  emit_text_buffer = mmap(NULL, 0x80000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT(emit_text_buffer != MAP_FAILED, "Failed to map code buffer: %s\n", strerror(errno));

  emit_data_buffer = mmap(NULL, 0x80000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT(emit_data_buffer != MAP_FAILED, "Failed to map code buffer: %s\n", strerror(errno));

  add_builtin("$unreachable", handle_builtin_unreachable);
  add_builtin("$arg", handle_builtin_arg);
  add_builtin("$argc", handle_builtin_argc);
  add_builtin("$entry", handle_builtin_entry);
  add_builtin("$syscall", handle_builtin_syscall);
  add_builtin("$sizeof", handle_builtin_sizeof);
  add_builtin("$read8", handle_builtin_read8);
  add_builtin("$read16", handle_builtin_read16);
  add_builtin("$read32", handle_builtin_read32);
  add_builtin("$read64", handle_builtin_read64);
  add_builtin("$write8", handle_builtin_write8);
  add_builtin("$write16", handle_builtin_write16);
  add_builtin("$write32", handle_builtin_write32);
  add_builtin("$write64", handle_builtin_write64);

  struct scope *root_scope = parse_file(realpath(argv[1], NULL));
  struct identifier *entry = lookup_ident(root_scope, "_start", 6, 0);

  ASSERT(entry != NULL, "No entry point (_start) was declared");
  ASSERT(entry->type == IDENT_FUNC, "Entry point (_start) must be a function");

  uint64_t data_length_aligned = ALIGN_UP(emitted_data_length, 0x1000);
  uint64_t text_addr = DATA_ADDR + data_length_aligned;

  struct elf_hdr elf;

  memcpy(elf.header.e_ident, "\x7F""ELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16); // elf_hdr

  elf.header.e_type = ET_EXEC;
  elf.header.e_machine = EM_X86_64;
  elf.header.e_version = EV_CURRENT;
  elf.header.e_entry = text_addr + entry->func.offset;
  elf.header.e_phoff = offsetof(struct elf_hdr, phdr);
  elf.header.e_shoff = 0;
  elf.header.e_flags = 0;

  elf.header.e_ehsize = 0;
  elf.header.e_phentsize = sizeof(Elf64_Phdr);
  elf.header.e_phnum = sizeof(elf.phdr) / sizeof(Elf64_Phdr);
  elf.header.e_shentsize = sizeof(Elf64_Shdr);
  elf.header.e_shnum = 0;
  elf.header.e_shstrndx = 0;

  elf.phdr[0].p_type = PT_LOAD;
  elf.phdr[0].p_flags = PF_R | PF_W;
  elf.phdr[0].p_offset = 0x1000;
  elf.phdr[0].p_vaddr = DATA_ADDR;
  elf.phdr[0].p_paddr = 0;
  elf.phdr[0].p_filesz = emitted_data_length;
  elf.phdr[0].p_memsz = emitted_data_length;
  elf.phdr[0].p_align = 0x1000;

  elf.phdr[1].p_type = PT_LOAD;
  elf.phdr[1].p_flags = PF_R | PF_W | PF_X;
  elf.phdr[1].p_offset = data_length_aligned + 0x1000;
  elf.phdr[1].p_vaddr = text_addr;
  elf.phdr[1].p_paddr = 0;
  elf.phdr[1].p_filesz = emitted_text_length;
  elf.phdr[1].p_memsz = emitted_text_length;
  elf.phdr[1].p_align = 0x1000;

  ftruncate(output_file, data_length_aligned + emitted_text_length + 0x1000);
  pwrite(output_file, &elf, sizeof(elf), 0);
  pwrite(output_file, emit_data_buffer, emitted_data_length, 0x1000);
  pwrite(output_file, emit_text_buffer, emitted_text_length, data_length_aligned + 0x1000);
}
