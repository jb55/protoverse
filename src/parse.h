
#ifndef PROTOVERSE_PARSE_H
#define PROTOVERSE_PARSE_H

#include "typedefs.h"
#include "cursor.h"

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
	O_OBJECT,
	O_TABLE,
	O_CHAIR,
	O_DOOR,
	O_LIGHT,
};

enum attribute_type {
	A_ID,
	A_TYPE,
	A_NAME,
	A_MATERIAL,
	A_CONDITION,
	A_COLOR,
	A_WIDTH,
	A_DEPTH,
	A_HEIGHT,
	A_LOCATION,
	A_SHAPE,
	A_STATE,
	A_DATA,
};

enum cell_state {
	STATE_ON,
	STATE_OFF,
	STATE_SLEEPING,
};

enum shape {
	SHAPE_RECTANGLE,
	SHAPE_CIRCLE,
	SHAPE_SQUARE,
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

union number {
	int integer;
	double fdouble;
};

struct bufstr {
	const char *ptr;
	int len;
};

struct data_attr {
	struct bufstr str;
	struct bufstr sym;
};

union attr_data {
	struct bufstr str;
	struct data_attr data_attr;
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

struct token_cursor {
	struct cursor c;
	enum token_error err;
	struct cursor_err err_data;
};

struct parser {
	struct token_cursor tokens;
	struct cursor attributes;
	struct cursor cells;
};

int parse_buffer(struct parser *parser, u8 *file_buf, int len, int *root);
int parse_file(struct parser *parser, const char *filename, int *root, u8 *buf, u32 bufsize);
int init_parser(struct parser *parser);
int free_parser(struct parser *parser);
void print_cell(struct cursor *attributes, struct cell *cell);
int tokenize_cells(unsigned char *buf, int buf_size, struct token_cursor *tokens);
int parse_cell(struct parser *parser, int *index);
void print_token_error(struct token_cursor *cursor);
const char *cell_type_str(enum cell_type);
const char *object_type_str(enum object_type);
struct cell *get_cell(struct cursor *cells, int index);
struct attribute *get_attr(struct cursor *attributes, int index);
int cell_attr_str(struct cursor *attributes, struct cell *cell, const char** name, int *len, enum attribute_type type);
const char *cell_name(struct cursor *attributes, struct cell *cell, int *len);

#endif /* PROTOVERSE_PARSE_H */
