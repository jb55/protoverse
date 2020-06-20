
#include "parse.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define tokdebug printf
#define MAX_ATTRIBUTES 16

enum known_symbol {
	S_OBJECT,
	S_SPACE,
	S_OBJECTS,
	S_NAME,
	S_TYPE,
	S_SHAPE,
	S_WIDTH,
	S_DEPTH,
	S_HEIGHT,
	S_CONDITION,
	S_LOCATION,
	S_MATERIAL,
};

enum tok_state {
	TS_OPEN,
	TS_CLOSE,
	TS_ATOM,
};

union token {
	struct tok_str str;
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
	struct cell *child;

	const char *name;
	const char *id;

	enum cell_type type;
};

static void copy_cursor(struct cursor *src, struct cursor *dest)
{
	dest->start = src->start;
	dest->p = src->p;
	dest->end = src->end;
	dest->err = src->err;
	memcpy(&dest->err_data, &src->err_data, sizeof(src->err_data));
}

void make_cursor(u8 *start, u8 *end, struct cursor *cursor)
{
	cursor->start = start;
	cursor->p = start;
	cursor->end = end;
	cursor->err = TE_OK;
	memset(&cursor->err_data, 0, sizeof(cursor->err_data));
}

static const char *token_error_string(enum token_error err)
{
	switch (err) {
	case TE_OK: return "all good";
	case TE_STR_START_CHAR: return "string didn't start with \"";
	case TE_SYM_START_CHAR: return "symbol didn't start with a-z";
	case TE_NUM_START_CHAR: return "number didn't start with 0-9 or -";
	case TE_SYM_CHAR: return "invalid symbol character";
	case TE_NUM_CHAR: return "invalid number character";
	case TE_SYM_OVERFLOW: return "symbol push overflow";
	case TE_UNEXPECTED_TOKEN: return "unexpected token during parsing";
	case TE_UNEXPECTED_SYMBOL: return "unexpected symbol during parsing";
	}

	return "unknown";
}

static const char *token_type_str(enum token_type type)
{
	switch (type) {
	case T_OPEN: return "(";
	case T_CLOSE: return ")";
	case T_SYMBOL: return "symbol";
	case T_STRING: return "string";
	case T_NUMBER: return "number";
	}

	return "unknown";
}

void print_token_error(struct cursor *cursor)
{
	if (cursor->err == TE_UNEXPECTED_TOKEN) {
		printf("error: %s: expected '%s' got '%s'\n",
		       token_error_string(cursor->err),
		       token_type_str(cursor->err_data.lex.expected),
		       token_type_str(cursor->err_data.lex.got));
	}
	else if (cursor->err == TE_UNEXPECTED_SYMBOL) {
		printf("error: %s: expected symbol '%.*s' got '%.*s'\n",
		       token_error_string(cursor->err),
		       cursor->err_data.symbol.expected.len,
		       cursor->err_data.symbol.expected.data,
		       cursor->err_data.symbol.got.len,
		       cursor->err_data.symbol.got.data);
	}
	else {
		int is_chr_data = cursor->err == TE_STR_START_CHAR ||
			cursor->err == TE_SYM_START_CHAR ||
			cursor->err == TE_NUM_START_CHAR ||
			cursor->err == TE_NUM_CHAR ||
			cursor->err == TE_SYM_CHAR;

		printf("\nerror: %s %.*s\n", token_error_string(cursor->err),
		       is_chr_data?1:0, (char*)&cursor->err_data.c);
	}

}

static int pull_byte(struct cursor *cursor, u8 *c)
{
	if (cursor->p + 1 >= cursor->end)
		return 0;

	*c = *cursor->p;
	cursor->p++;

	return 1;
}


static int push_byte(struct cursor *cursor, u8 c)
{
	if (cursor->p + 1 >= cursor->end) {
		return 0;
	}

	*cursor->p = c;
	cursor->p++;

	return 1;
}


static int pull_data(struct cursor *cursor, u8 *data, int len)
{
	if (cursor->p + len >= cursor->end) {
		return 0;
	}

	memcpy(data, cursor->p, len);
	cursor->p += len;

	return 1;
}

static int push_data(struct cursor *cursor, u8 *data, int len)
{
	if (cursor->p + len >= cursor->end) {
		printf("push_data oob\n");
		return 0;
	}

	memcpy(cursor->p, data, len);
	cursor->p += len;

	return 1;
}

static void print_spaces(int n)
{
	int i;
	for (i = 0; i < n; i++)
		putchar(' ');
}

static int push_token_data(struct cursor *tokens,
			   enum token_type token,
			   void *token_data, int token_data_size)
{
	static int depth = 0;
	struct tok_str *str;
	int ok;
	ok = push_byte(tokens, token);
	if (!ok) return 0;

	switch (token) {

	case T_OPEN:
		depth++;
		break;

	case T_CLOSE:
		depth--;
		break; /* nothing to write after these tokens */

	case T_NUMBER:
	case T_SYMBOL:

		/* fallthrough */
	case T_STRING:
		print_spaces(depth*2);
		str = (struct tok_str*)token_data;
		if (token == T_STRING) {
			tokdebug("str \"%.*s\"", str->len, str->data);
		} else if (token == T_NUMBER) {
			tokdebug("num %.*s", str->len, str->data);
		} else {
			tokdebug("sym %.*s", str->len, str->data);
		}
		ok = push_data(tokens, token_data, token_data_size);
		if (!ok) return 0;
		printf("\n");
		break;
	}


	return 1;
}


static int push_token(struct cursor *tokens, enum token_type token)
{
	return push_token_data(tokens, token, NULL, 0);
}

static int push_symbol(struct cursor *tokens, struct tok_str symbol)
{
	return push_token_data(tokens, T_SYMBOL, &symbol, sizeof(symbol));
}

static int push_string(struct cursor *tokens, struct tok_str str)
{
	return push_token_data(tokens, T_STRING, &str, sizeof(str));
}

static int push_number(struct cursor *tokens, struct tok_str str)
{
	return push_token_data(tokens, T_NUMBER, &str, sizeof(str));
}


static int is_start_symbol_char(char c)
{
	return c >= 'a' && c <= 'z';
}

static int is_symbol_char(char c)
{
	return is_start_symbol_char(c) || c == '-' || c == '_' ||
		(c >= '0' && c <= '9');
}

static int pull_escaped_char(struct cursor *cursor, u8 *c)
{
	int ok;

	ok = pull_byte(cursor, c);
	if (!ok)
		return 0;

	if (*c != '\\') {
		return 1;
	}

	ok = pull_byte(cursor, c);

	/* we saw an escape char but input ended!? */
	if (!ok) {
		return 0;
	}

	return 2;
}

static int pull_number(struct cursor *cursor, u8 **start)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;

	*start = temp.p = cursor->p;
	temp.end = cursor->end;

	while (1) {
		ok = pull_byte(&temp, &c);
		if (!ok) return 0;

		/* first char should start with a letter */
		if (chars == 0 && !isdigit(c) && c != '-') {
			cursor->err = TE_NUM_START_CHAR;
			cursor->err_data.c = c;
			return 0;
		} else if (chars > 0 && (isspace(c) || c == ')')) {
			/* we got a number */
			break;
		} else if (chars > 0 && !isdigit(c) && c != '.') {
			cursor->err = TE_NUM_CHAR;
			cursor->err_data.c = c;
			return 0;
		} 
	
		chars++;

		if (!ok) {
			cursor->err = TE_SYM_OVERFLOW;
			return 0;
		}
	}

	if (!ok) {
		cursor->err = TE_SYM_OVERFLOW;
		return 0;
	}

	cursor->p = temp.p-1;
	cursor->err = TE_OK;

	/* remove the first counted quote since this was not pushed */
	return chars;
}

static int pull_string(struct cursor *cursor, u8 **start)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;

	copy_cursor(cursor, &temp);

	while (1) {
		ok = pull_escaped_char(&temp, &c);
		if (!ok) return 0;

		if (chars == 1)
			*start = temp.p;

		/* first char should start with a letter */
		if (chars == 0 && c != '"') {
			cursor->err = TE_STR_START_CHAR;
			cursor->err_data.c = c;
			return 0;
		} else if (chars == 0 && c == '"') {
			/* this increment will get removed at end */
			chars++;
			continue;
		} else if (chars > 0 && c == '"' && ok == 1) {
			/* ok == 2 would mean that it was escaped, so
			   we're done here */
			break;
		}

		chars++;

		if (!ok) {
			cursor->err = TE_SYM_OVERFLOW;
			return 0;
		}
	}

	if (!ok) {
		cursor->err = TE_SYM_OVERFLOW;
		return 0;
	}

	copy_cursor(&temp, cursor);

	/* remove the first counted quote since this was not pushed */
	return --chars;
}

static int pull_symbol(struct cursor *cursor, u8 **start)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;

	copy_cursor(cursor, &temp);

	*start = temp.p;

	while (1) {
		ok = pull_byte(&temp, &c);
		if (!ok) return 0;

		/* first char should start with a letter */
		if (chars == 0 && !is_start_symbol_char(c)) {
			cursor->err = TE_SYM_START_CHAR;
			cursor->err_data.c = c;
			return 0;
		} else if (chars > 0 && (isspace(c) || c == ')')) {
			/* we're done here */
			break;
		} else if (chars > 0 && !is_symbol_char(c)) {
			cursor->err = TE_SYM_CHAR;
			cursor->err_data.c = c;
			return 0;
		}

		chars++;

		if (!ok) {
			cursor->err = TE_SYM_OVERFLOW;
			return 0;
		}
	}

	if (!ok) {
		cursor->err = TE_SYM_OVERFLOW;
		return 0;
	}

	temp.p--;
	copy_cursor(&temp, cursor);

	return chars;
}

static int read_and_push_atom(struct cursor *cursor, struct cursor *tokens)
{
	struct tok_str str;
	u8 *start;
	int ok;

	ok = pull_symbol(cursor, &start);
	if (ok) {
		str.len  = ok;
		str.data = start;
		ok = push_symbol(tokens, str);
		if (!ok) {
			printf("read_and_push_atom identifier push overflow\n");
			return 0;
		}
		return 1;
	}

	ok = pull_string(cursor, &start);
	if (ok) {
		str.len  = ok;
		str.data = start;
		ok = push_string(tokens, str);
		if (!ok) {
			printf("read_and_push_atom string push overflow\n");
			return 0;
		}
		return 1;
	}

	start = cursor->p;
	ok = pull_number(cursor, &start);
	if (ok) {
		str.len  = ok;
		str.data = start;
		ok = push_number(tokens, str);
		if (!ok) {
			printf("read_and_push_atom number push overflow\n");
			return 0;
		}
		return 1;
	}

	/* TODO: read_number */

	return 0;
}

int tokenize_cells(u8 *buf, int buf_size, struct cursor *tokens)
{
	enum tok_state state;
	struct cursor cursor;
	/* u8 *start = buf; */
	u8 *token_buf = tokens->p;
	u8 c;
	int ok;

	cursor.p = buf;
	cursor.end = buf + buf_size;

	state = TS_OPEN;

	while (cursor.p < cursor.end) {
		ok = pull_byte(&cursor, &c);
		if (!ok) break;

		if (state == TS_OPEN) {
			if (isspace(c))
				continue;

			if (c != '(') {
				printf("expected '(' or whitespace\n");
				return 0;
			}

			push_token(tokens, T_OPEN);
			state = TS_ATOM;
			continue;
		}
		else if (state == TS_ATOM) {
			if (isspace(c))
				continue;

			if (c == '(') {
				push_token(tokens, T_OPEN);
				continue;
			}

			if (c == ')') {
				push_token(tokens, T_CLOSE);
				continue;
			}

			cursor.p--;
			/* printf("\nat %c (%ld) before reading atom\n", *cursor.p, cursor.p - start); */
			ok = read_and_push_atom(&cursor, tokens);
			if (!ok) {
				print_token_error(&cursor);
				return 0;
			}

		}
	}

	/* just seal the buffer now since we won't be adding to it */
	tokens->end = tokens->p;
	tokens->p = token_buf;

	return 1;
}


static int pull_token_data(struct cursor *tokens, union token *token,
			   enum token_type type)
{
	int ok;

	switch (type) {
	case T_OPEN:
	case T_CLOSE:
		return 1;
	case T_STRING:
	case T_SYMBOL:
	case T_NUMBER:
		ok = pull_data(tokens, (void*)&token->str,
			       sizeof(struct tok_str));
		return ok;
	}

	return 0;
}

static int pull_token(struct cursor *tokens,
		      union token *token,
		      enum token_type expected_type)
{
	struct cursor temp;
	enum token_type type;
	u8 c;
	int ok;

	copy_cursor(tokens, &temp);

	ok = pull_byte(&temp, &c);
	if (!ok) return 0;

	type = (enum token_type)c;

	if (type != expected_type) {
		tokens->err = TE_UNEXPECTED_TOKEN;
		tokens->err_data.lex.expected = expected_type;
		tokens->err_data.lex.got = type;
		return 0;
	}

	ok = pull_token_data(&temp, token, type);
	if (!ok) {
		return 0;
	}

	tokens->p = temp.p;

	return 1;
}

/*
 *  PARSING
 */


static int pull_open(struct cursor *tokens)
{
	return pull_token(tokens, NULL, T_OPEN);
}

static int pull_symbol_token(struct cursor *tokens, struct tok_str *str)
{
	union token token;
	int ok;

	ok = pull_token(tokens, &token, T_SYMBOL);
	if (!ok) return 0;

	str->data = token.str.data;
	str->len = token.str.len;

	return 1;
}

static int memeq(void *buf, int buf_len, void *buf2, int buf2_len)
{
	if (buf_len != buf2_len)
		return 0;

	return memcmp(buf, buf2, buf_len) == 0;
}

static int symbol_eq(struct tok_str *a, char *b, int b_len)
{
	return memeq(a->data, a->len, b, b_len);
}

static int parse_symbol(struct cursor *tokens, const char *match)
{
	int ok;
	struct tok_str str;

	ok = pull_symbol_token(tokens, &str);

	if (!ok)
		return 0;

	if (!symbol_eq(&str, match, strlen(match)))
		return 0;

	return 1;
}

static int parse_symbol(struct cursor *tokens, const char *match)
{
	int ok;
	struct tok_str str;

	ok = pull_symbol_token(tokens, &str);

	if (!ok)
		return 0;

	if (!symbol_eq(&str, match, strlen(match)))
		return 0;

	return 1;
}

static int parse_shape_attr(struct cursor *tokens, struct attribute *attr)
{
	struct cursor temp;
	struct tok_str str;
	int ok;

	copy_cursor(tokens, &temp);

	ok = parse_symbol(&temp, "shape");
	if (!ok)
		return 0;

	ok = pull_symbol_token(&temp, &str);

	if (!ok)
		return 0;

	if (symbol_eq(&str, "rectangle", 9)) {
		attr->data.shape = SHAPE_RECTANGLE;
	}
	else {
		tokens->err = TE_UNEXPECTED_SYMBOL;
		tokens->err_data.symbol.expected.data = (u8*)"rectangle";
		tokens->err_data.symbol.expected.len = 9;
		tokens->err_data.symbol.got.data = str.data;
		tokens->err_data.symbol.got.len = str.len;
	}

	copy_cursor(&temp, tokens);

	return 1;
}

static int parse_attribute(struct cursor *tokens, struct attribute *attr)
{
	int ok;

	ok = parse_shape_attr(tokens, attr);
	if (ok) return 1;

	return 0;
}


static int cursor_index(struct cursor *cursor, int elem_size)
{
	return (cursor->p - cursor->start) / elem_size;
}

static int parse_attributes(struct cursor *tokens,
			    struct cursor *attributes,
			    int attr_inds[2])
{
	int ok;
	int index = -1;
	int first = 1;
	int parsed = 1;
	struct attribute attr;

	while (1) {
		ok = parse_attribute(tokens, &attr);

		if (!ok) break;

		index = cursor_index(attributes, sizeof(attr));

		ok = push_data(attributes, (u8*)&attr, sizeof(attr));
		if (!ok) {
			printf("attribute data overflow\n");
			return 0;
		}

		parsed++;

		if (first) {
			first = 0;
			attr_inds[0] = index;
		}
	}

	attr_inds[1] = index;

	return parsed;
}

/*
static int parse_group(struct cursor *tokens)
{
	int ok;
	struct tok_str str;

	ok = pull_symbol_token(tokens, &str);
	if (!ok) return 0;

	if (!memeq(str.data, str.len, "group", 5))
		return 0;

	parse_attributes(&tokens)
}
*/

static int parse_room(struct cursor *tokens,
		      struct cursor *attributes,
		      struct cell *cell)
{
	int ok;
	struct cursor temp;
	struct tok_str str;
	int attr_inds[2];

	(void)cell;

	copy_cursor(tokens, &temp);

	ok = pull_symbol_token(&temp, &str);
	if (!ok) return 0;

	if (!symbol_eq(&str, "room", 4))
		return 0;

	/* 0 attributes returns 1, 1 attrs returns 2, etc
	   0 is a real error, an attribute push overflow */
	ok = parse_attributes(&temp, attributes, attr_inds);
	if (!ok)
		return 0;

	/* parse_object(tokens, cell); */

	return 1;
}

static int parse_cell(struct cursor *tokens,
		      struct cursor *attributes,
		      struct cell *cell)
{
	int ok;
	/* ok = parse_group(tokens, cell); */
	/* if (ok) return 1; */

	ok = parse_room(tokens, attributes, cell);
	if (ok) return 1;

	/* ok = parse_object(tokens, cell); */

	return 0;
}

int parse_cells(struct cursor *tokens, struct cursor *attributes)
{
	struct cell cell;
	int ok;

	while (1) {
		ok = pull_open(tokens);
		if (!ok) return 0;

		/* cell identifier */
		ok = parse_cell(tokens, attributes, &cell);
		if (!ok) return 0;

	}


	return 1;
}
