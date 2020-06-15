
#ifndef PROTOVERSE_PARSE_H
#define PROTOVERSE_PARSE_H

#include "typedefs.h"

struct cursor {
	u8 *p;
	u8 *end;
	enum token_error err;
	union {
		char c;
	} err_data;
};

enum token_error {
	TE_OK,
	TE_STR_START_CHAR,
	TE_NUM_START_CHAR,
	TE_SYM_START_CHAR,
	TE_SYM_CHAR,
	TE_NUM_CHAR,
	TE_SYM_OVERFLOW,
};


int tokenize_space(unsigned char *buf, int buf_size, u8 *token_buf, int token_buf_size, struct cursor *tokens);
int parse_cell(u8 *token_buf, int token_buf_size);

#endif /* PROTOVERSE_PARSE_H */
