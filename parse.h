
#ifndef PROTOVERSE_PARSE_H
#define PROTOVERSE_PARSE_H

#include "typedefs.h"

enum token_error {
	TE_OK,
	TE_STR_START_CHAR,
	TE_NUM_START_CHAR,
	TE_SYM_START_CHAR,
	TE_SYM_CHAR,
	TE_NUM_CHAR,
	TE_UNEXPECTED_TOKEN,
	TE_UNEXPECTED_SYMBOL,
	TE_SYM_OVERFLOW,
};

enum token_type {
	T_OPEN,
	T_CLOSE,
	T_STRING,
	T_SYMBOL,
	T_NUMBER,
};

struct tok_str {
	u8 *data;
	int len;
};


struct cursor {
	u8 *start;
	u8 *p;
	u8 *end;
	enum token_error err;
	union {
		struct {
			struct tok_str expected;
			struct tok_str got;
		} symbol;
		struct {
			enum token_type expected;
			enum token_type got;
		} lex;
		char c;
	} err_data;
};

void make_cursor(u8 *start, u8 *end, struct cursor *cursor);
int tokenize_cells(unsigned char *buf, int buf_size, struct cursor *tokens);
int parse_cells(struct cursor *tokens, struct cursor *attributes);
void print_token_error(struct cursor *cursor);

#endif /* PROTOVERSE_PARSE_H */
