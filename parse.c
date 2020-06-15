
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

enum token_type {
	T_OPEN,
	T_CLOSE,
	T_STRING,
	T_SYMBOL,
	T_NUMBER,
};

enum tok_state {
	TS_OPEN,
	TS_CLOSE,
	TS_ATOM,
};

struct tok_str {
	u8 *data;
	int len;
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
};

struct cell {
	int attributes[MAX_ATTRIBUTES];

	const char *name;
	const char *id;

	enum cell_type type;
};

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
	}

	return "unknown";
}

static void print_token_error(struct cursor *cursor)
{
	int is_chr_data = cursor->err == TE_STR_START_CHAR ||
		cursor->err == TE_SYM_START_CHAR ||
		cursor->err == TE_NUM_START_CHAR ||
		cursor->err == TE_NUM_CHAR ||
		cursor->err == TE_SYM_CHAR;
	printf("\nerror: %s %.*s\n", token_error_string(cursor->err),
	       is_chr_data?1:0, (char*)&cursor->err_data.c);
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

static int pull_number(struct cursor *cursor, u8 *buf, int buf_len)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;
	struct cursor buf_cursor;

	temp.p = cursor->p;
	temp.end = cursor->end;

	buf_cursor.p = buf;
	buf_cursor.end = buf + buf_len;

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
		ok = push_byte(&buf_cursor, c);
		chars++;

		if (!ok) {
			cursor->err = TE_SYM_OVERFLOW;
			return 0;
		}
	}

	ok = push_byte(&buf_cursor, 0);
	chars++;

	if (!ok) {
		cursor->err = TE_SYM_OVERFLOW;
		return 0;
	}

	cursor->p = temp.p-1;
	cursor->err = TE_OK;

	/* remove the first counted quote since this was not pushed */
	return chars;
}

static int pull_string(struct cursor *cursor, u8 *buf, int buf_len)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;
	struct cursor buf_cursor;

	temp.p = cursor->p;
	temp.end = cursor->end;

	buf_cursor.p = buf;
	buf_cursor.end = buf + buf_len;

	while (1) {
		ok = pull_escaped_char(&temp, &c);
		if (!ok) return 0;

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

		ok = push_byte(&buf_cursor, c);
		chars++;

		if (!ok) {
			cursor->err = TE_SYM_OVERFLOW;
			return 0;
		}
	}

	ok = push_byte(&buf_cursor, 0);
	chars++;

	if (!ok) {
		cursor->err = TE_SYM_OVERFLOW;
		return 0;
	}

	cursor->p = temp.p;
	cursor->err = TE_OK;

	/* remove the first counted quote since this was not pushed */
	return --chars;
}

static int pull_symbol(struct cursor *cursor, u8 *buf, int buf_len)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;
	struct cursor sym_cursor;

	temp.p = cursor->p;
	temp.end = cursor->end;

	sym_cursor.p = buf;
	sym_cursor.end = buf + buf_len;

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

		ok = push_byte(&sym_cursor, c);
		chars++;

		if (!ok) {
			cursor->err = TE_SYM_OVERFLOW;
			return 0;
		}
	}

	ok = push_byte(&sym_cursor, 0);
	chars++;

	if (!ok) {
		cursor->err = TE_SYM_OVERFLOW;
		return 0;
	}

	cursor->p = temp.p-1;
	cursor->end = temp.end;
	cursor->err = TE_OK;

	return chars;
}

static int read_and_push_atom(struct cursor *cursor, struct cursor *tokens)
{
	u8 buf[255];
	struct tok_str str;
	int ok;

	ok = pull_symbol(cursor, buf, sizeof(buf));
	if (ok) {
		str.len  = ok;
		str.data = buf;
		ok = push_symbol(tokens, str);
		if (!ok) {
			printf("read_and_push_atom identifier push overflow\n");
			return 0;
		}
		return 1;
	}


	ok = pull_string(cursor, buf, sizeof(buf));
	if (ok) {
		str.len  = ok;
		str.data = buf;
		ok = push_string(tokens, str);
		if (!ok) {
			printf("read_and_push_atom string push overflow\n");
			return 0;
		}
		return 1;
	}

	ok = pull_number(cursor, buf, sizeof(buf));
	if (ok) {
		str.len  = ok;
		str.data = buf;
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

int tokenize_space(u8 *buf, int buf_size, u8 *token_buf,
		   int token_buf_size, struct cursor *tokens)
{
	enum tok_state state;
	struct cursor cursor;
	/* u8 *start = buf; */
	u8 c;
	int ok;

	cursor.p = buf;
	cursor.end = buf + buf_size;

	tokens.p = token_buf;
	tokens.end = token_buf + token_buf_size;

	state = TS_OPEN;

	while (cursor.p < cursor.end) {
		ok = pull_byte(&cursor, &c);
		if (!ok) return 0;

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

	temp.p = tokens->p;
	temp.end = tokens->end;

	ok = pull_byte(&temp, &c);
	if (!ok) return 0;

	type = (enum token_type)c;

	ok = pull_token_data(&temp, token, type);
	if (!ok) {
		return 0;
	}

	if (type != expected_type) {
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

int parse_cell(struct cursor *tokens)
{
	struct cursor tokens;
	struct tok_str str;
	int ok;

	tokens.p = token_buf;
	tokens.end = token_buf + token_buf_size;

	while (1) {
		ok = pull_open(&tokens);
		if (!ok) return 0;

		/* cell identifier */
		ok = pull_symbol_token(&tokens, &str);
		if (!ok) return 0;

		printf("got token: %.*s\n", str.len, str.data);
	}


	return 1;
}
