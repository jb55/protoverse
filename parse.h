
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
	TE_SYM_OVERFLOW,
};

enum token_type {
	T_OPEN,
	T_CLOSE,
	T_STRING,
	T_SYMBOL,
	T_NUMBER,
};


struct cursor {
	u8 *start;
	u8 *p;
	u8 *end;
	enum token_error err;
	union {
		char c;
		struct {
			enum token_type expected;
			enum token_type got;
		} parse;
	} err_data;
};

void make_cursor(u8 *start, u8 *end, struct cursor *cursor);
int tokenize_cells(unsigned char *buf, int buf_size, struct cursor *tokens);
int parse_cells(struct cursor *tokens);
void print_token_error(struct cursor *cursor);

#endif /* PROTOVERSE_PARSE_H */
