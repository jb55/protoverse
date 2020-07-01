
#ifndef PROTOVERSE_PARSE_H
#define PROTOVERSE_PARSE_H

#include "typedefs.h"

#define MAX_ATTRIBUTES 24
#define MAX_CHILDREN 24
#define ARRAY_SIZE(x) ((int)(sizeof(x) / sizeof((x)[0])))

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
	C_ROOM,
	C_OBJECT,
};

enum object_type {
	O_TABLE,
	O_DOOR,
	O_LIGHT,
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

struct cursor_err {
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
	};
	int pos;
};

struct cursor {
	u8 *start;
	u8 *p;
	u8 *end;
	enum token_error err;
	struct cursor_err err_data;
};

union number {
	int integer;
	double fdouble;
};

union attr_data {
	struct {
		const char *ptr;
		int len;
	} str;
	enum shape shape;
	union number number;
};

struct attribute {
	union attr_data data;
	enum attribute_type type;
};

struct cell {
	u16 attributes[MAX_ATTRIBUTES];
	u16 children[MAX_CHILDREN];
	int n_attributes;
	int n_children;

	enum cell_type type;
	enum object_type obj_type;
};

struct parser {
	struct cursor *tokens;
	struct cursor *attributes;
	struct cursor *cells;
};


void make_cursor(u8 *start, u8 *end, struct cursor *cursor);
int tokenize_cells(unsigned char *buf, int buf_size, struct cursor *tokens);
int parse_cell(struct parser *parser, u16 *index);
void print_token_error(struct cursor *cursor);
int cursor_index(struct cursor *cursor, int elem_size);
const char *cell_type_str(enum cell_type);
const char *object_type_str(enum object_type);
int cell_name(struct cursor *attributes, struct cell *cell, const char** name, int *len);
struct cell *get_cell(struct cursor *cells, u16 index);

#endif /* PROTOVERSE_PARSE_H */
