
#ifndef PROTOVERSE_PARSE_H
#define PROTOVERSE_PARSE_H

#include "typedefs.h"

#define MAX_ATTRIBUTES 24

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

enum cell_type {
	C_GROUP,
	C_SPACE,
	C_OBJECT,
};

enum attribute_type {
	A_ID,
	A_TYPE,
	A_NAME,
	A_MATERIAL,
	A_CONDITION,
	A_WIDTH,
	A_DEPTH,
	A_HEIGHT,
	A_LOCATION,
	A_SHAPE,
};

enum shape {
	SHAPE_RECTANGLE
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

union cursor_err {
	struct {
		struct tok_str expected;
		struct tok_str got;
	} symbol;
	struct {
		enum token_type expected;
		enum token_type got;
	} lex;
	int pos;
	char c;
};

struct cursor {
	u8 *start;
	u8 *p;
	u8 *end;
	enum token_error err;
	union cursor_err err_data;
};

union attr_data {
	struct {
		const char *ptr;
		int len;
	} str;
	enum shape shape;
	int integer;
	double fdouble;
};

struct attribute {
	union attr_data data;
	enum attribute_type type;
};

struct cell {
	int attributes[MAX_ATTRIBUTES];
	int n_attributes;
	struct cell *child;

	const char *name;
	const char *id;

	enum cell_type type;
};


void make_cursor(u8 *start, u8 *end, struct cursor *cursor);
int tokenize_cells(unsigned char *buf, int buf_size, struct cursor *tokens);
int parse_cells(struct cursor *tokens, struct cursor *attributes);
void print_token_error(struct cursor *cursor);

#endif /* PROTOVERSE_PARSE_H */
