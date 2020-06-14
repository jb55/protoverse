
#include "parse.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define tokdebug printf

enum token_error {
	TE_OK,
	TE_SYM_START_CHAR,
	TE_SYM_CHAR,
	TE_SYM_OVERFLOW,
};

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

struct cursor {
	u8 *p;
	u8 *end;
	enum token_error err;
	union {
		char c;
	} err_data;
};

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

static int push_token_data(struct cursor *tokens,
			   enum token_type token,
			   void *token_data, int token_data_size)
{
	struct tok_str *str;
	int ok;
	ok = push_byte(tokens, token);
	if (!ok) return 0;

	switch (token) {
	case T_NUMBER:
		tokdebug("NUM");
		break;

	case T_OPEN:
		tokdebug("(");
		break;

	case T_CLOSE:
		tokdebug(")");
		break; /* nothing to write after these tokens */

	case T_SYMBOL:
		tokdebug("S_");

		/* fallthrough */
	case T_STRING:
		str = (struct tok_str*)token_data;
		if (token == T_STRING) {
			tokdebug("\"%.*s\" ", str->len, str->data);
		}
		else {
			tokdebug("%.*s ", str->len, str->data);
		}
		ok = push_data(tokens, token_data, token_data_size);
		if (!ok) return 0;
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


static int is_start_symbol_char(char c)
{
	return c >= 'a' && c <= 'z';
}

static int is_symbol_char(char c)
{
	return is_start_symbol_char(c) || c == '-' || c == '_' ||
		(c >= '0' && c <= '9');
}

static int pull_string(struct cursor *cursor, u8 *buf, int buf_len)
{
	(void)cursor;
	(void)buf;
	(void)buf_len;
	return 0;
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
		} else if (chars > 0 && isspace(c)) {
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

	cursor->p = temp.p;
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
		str.len = ok;
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
		str.len = ok;
		str.data = buf;
		ok = push_string(tokens, str);
		if (!ok) {
			printf("read_and_push_atom string push overflow\n");
			return 0;
		}
		return 1;
	}

	/* TODO: read_number */

	return 0;
}

int tokenize_space(u8 *buf, int buf_size, u8 *token_buf, int token_buf_size)
{
	enum tok_state state;
	struct cursor cursor;
	struct cursor tokens;
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

			push_token(&tokens, T_OPEN);
			state = TS_ATOM;
			continue;
		}
		else if (state == TS_ATOM) {
			if (isspace(c))
				continue;

			if (c == '(') {
				push_token(&tokens, T_OPEN);
				continue;
			}

			if (c == ')') {
				push_token(&tokens, T_CLOSE);
				continue;
			}

			cursor.p--;
			ok = read_and_push_atom(&cursor, &tokens);
			if (!ok) return 0;

		}
	}

	return 1;
}
