
#include "parse.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

#ifdef DEBUG
#define tokdebug printf
#else
#define tokdebug(...)
#define print_spaces(...)
#endif

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

int cursor_index(struct cursor *cursor, int elem_size)
{
	return (cursor->p - cursor->start) / elem_size;
}

#ifdef DEBUG
static const char *attr_type_str(enum attribute_type type)
{
	switch (type) {
	case A_CONDITION: return "condition";
	case A_DEPTH: return "depth";
	case A_HEIGHT: return "height";
	case A_ID: return "id";
	case A_LOCATION: return "location";
	case A_MATERIAL: return "material";
	case A_NAME: return "name";
	case A_SHAPE: return "shape";
	case A_TYPE: return "type";
	case A_WIDTH: return "width";
	}

	return "unknown";
}
#endif

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

void print_cell(struct cursor *attributes, struct cell *cell)
{
	const char *name;
	int name_len;

	if (cell->type == C_GROUP) {
		printf("---\n");
		return;
	}

	cell_name(attributes, cell, &name, &name_len);

	printf("%.*s%s%s\n", name_len, name, name_len > 0?" ":"",
	       cell->type == C_OBJECT
	       ? object_type_str(cell->obj_type)
	       : cell_type_str(cell->type));
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

	printf("UNUSUAL: unknown token_type %d\n", type);

	return "unknown";
}

void print_token_error(struct cursor *cursor)
{
	printf("error [%d]: ", cursor->err_data.pos);
	if (cursor->err == TE_UNEXPECTED_TOKEN) {
		printf("%s: expected '%s' got '%s'\n",
		       token_error_string(cursor->err),
		       token_type_str(cursor->err_data.lex.expected),
		       token_type_str(cursor->err_data.lex.got));
	}
	else if (cursor->err == TE_UNEXPECTED_SYMBOL) {
		printf("%s: expected symbol '%.*s' got '%.*s'\n",
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
	if (cursor->p + 1 > cursor->end)
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

static int push_int(struct cursor *cursor, int i)
{
	return push_data(cursor, (u8*)&i, sizeof(i));
}

static int push_u16(struct cursor *cursor, u16 i)
{
	return push_data(cursor, (u8*)&i, sizeof(i));
}

#ifdef DEBUG
static void print_spaces(int n)
{
	int i;
	for (i = 0; i < n; i++)
		putchar(' ');
}
#endif

static int push_token_data(struct cursor *tokens,
			   enum token_type token,
			   void *token_data, int token_data_size)
{
	static int depth = 0;
#ifdef DEBUG
	struct tok_str *str;
#endif
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
#ifdef DEBUG
		print_spaces(depth*2);
		str = (struct tok_str*)token_data;
		if (token == T_STRING) {
			tokdebug("str \"%.*s\"", str->len, str->data);
		} else if (token == T_NUMBER) {
			tokdebug("num %.*s", str->len, str->data);
		} else {
			tokdebug("sym %.*s", str->len, str->data);
		}
#endif
		ok = push_data(tokens, token_data, token_data_size);
		if (!ok) return 0;
#ifdef DEBUG
		printf("\n");
#endif
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

static int pull_string(struct cursor *cursor, u8 **start, int *len)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;

	copy_cursor(cursor, &temp);

	while (1) {
		if (chars == 0)
			*start = temp.p+1;

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
	*len = temp.p - *start - 1;
	return 1;
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

static void init_cell(struct cell *cell)
{
	memset(cell, 0, sizeof(*cell));
}

static int read_and_push_atom(struct cursor *cursor, struct cursor *tokens)
{
	struct tok_str str;
	u8 *start;
	int ok, len;

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

	ok = pull_string(cursor, &start, &len);
	if (ok) {
		str.len  = len;
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

static int pull_token_type(struct cursor *cursor, enum token_type *type)
{
	int ok;
	u8 c;

	ok = pull_byte(cursor, &c);
	if (!ok) return 0;

	*type = (enum token_type)c;
	return 1;
}

static int pull_token(struct cursor *tokens,
		      union token *token,
		      enum token_type expected_type)
{
	struct cursor temp;
	enum token_type type;
	int ok;

	copy_cursor(tokens, &temp);

	ok = pull_token_type(&temp, &type);
	if (!ok) return 0;

	if (type != expected_type) {
		tokens->err = TE_UNEXPECTED_TOKEN;
		tokens->err_data.lex.expected = expected_type;
		tokens->err_data.lex.got = type;
		tokens->err_data.pos = cursor_index(&temp, 1);
		return 0;
	}

	ok = pull_token_data(&temp, token, type);
	if (!ok) {
		return 0;
	}

	copy_cursor(&temp, tokens);

	return 1;
}

#ifdef DEBUG
static void print_token_data(union token *token, enum token_type type)
{
	switch (type) {
	case T_OPEN:
		printf("(");
		return;
	case T_CLOSE:
		printf(")");
		return;
	case T_NUMBER:
	case T_SYMBOL:
		printf("%.*s", token->str.len, token->str.data);
		return;
	case T_STRING:
		printf("\"%.*s\"", token->str.len, token->str.data);
		return;
	}
}


static void print_current_token(struct cursor *tokens)
{
	struct cursor temp;
	enum token_type type;
	union token token;
	int ok;

	copy_cursor(tokens, &temp);

	ok = pull_token_type(&temp, &type);
	if (!ok) {
		printf("could not peek token\n");
		return;
	}

	printf("current token: %s ", token_type_str(type));

	ok = pull_token_data(&temp, &token, type);
	if (!ok) {
		printf("[could not peek token data]\n");
		return;
	}

	print_token_data(&token, type);
	printf("\n");
}
#endif

/*
 *  PARSING
 */


static int parse_open(struct cursor *tokens)
{
	return pull_token(tokens, NULL, T_OPEN);
}

static int parse_close(struct cursor *tokens)
{
	return pull_token(tokens, NULL, T_CLOSE);
}

static int parse_stringy_token(struct cursor *tokens,
			       struct tok_str *str,
			       enum token_type type)
{
	union token token;
	int ok;

	ok = pull_token(tokens, &token, type);
	if (!ok) return 0;

	str->data = token.str.data;
	str->len = token.str.len;

	return 1;
}


static int pull_symbol_token(struct cursor *tokens, struct tok_str *str)
{
	return parse_stringy_token(tokens, str, T_SYMBOL);
}

static int pull_number_token(struct cursor *tokens, struct tok_str *str)
{
	return parse_stringy_token(tokens, str, T_NUMBER);
}

static int parse_number(struct cursor *tokens, union number *number)
{
	int ok;
	struct tok_str str;
	char *end;

	ok = pull_number_token(tokens, &str);
	if (!ok) return 0;

	/* TODO: float numbers */
	number->integer = strtol((char*)str.data, &end, 10);

	if ((u8*)end != (str.data + str.len)) {
		printf("parse_number failed\n");
		return 0;
	}

	return 1;
}

static void *index_cursor(struct cursor *cursor, u16 index, int elem_size)
{
	u8 *p;
	p = &cursor->start[elem_size * index];

	if (p > cursor->end)
		return NULL;

	return (void*)p;
}


static struct attribute *get_attr(struct cursor *attributes, u16 index)
{
	return (struct attribute*)index_cursor(attributes, index,
					       sizeof(struct attribute));
}

struct cell *get_cell(struct cursor *cells, u16 index)
{
	return (struct cell*)index_cursor(cells, index,
					  sizeof(struct cell));
}


static int memeq(void *buf, int buf_len, void *buf2, int buf2_len)
{
	if (buf_len != buf2_len)
		return 0;

	return memcmp(buf, buf2, buf_len) == 0;
}

static int symbol_eq(struct tok_str *a, const char *b, int b_len)
{
	return memeq(a->data, a->len, (char*)b, b_len);
}

static int parse_symbol(struct cursor *tokens, const char *match)
{
	int ok;
	struct tok_str str;

	ok = pull_symbol_token(tokens, &str);
	if (!ok) return 0;

	if (!symbol_eq(&str, match, strlen(match)))
		return 0;

	return 1;
}

static int parse_shape(struct cursor *tokens, struct attribute *attr)
{
	struct cursor temp;
	struct tok_str str;
	int ok;

	copy_cursor(tokens, &temp);

	ok = parse_symbol(&temp, "shape");
	if (!ok) return 0;

	attr->type = A_SHAPE;

	ok = pull_symbol_token(&temp, &str);
	if (!ok) return 0;

	if (symbol_eq(&str, "rectangle", 9)) {
		attr->data.shape = SHAPE_RECTANGLE;
	} else {
		tokens->err = TE_UNEXPECTED_SYMBOL;
		tokens->err_data.symbol.expected.data = (u8*)"rectangle";
		tokens->err_data.symbol.expected.len = 9;
		tokens->err_data.symbol.got.data = str.data;
		tokens->err_data.symbol.got.len = str.len;
	}

	copy_cursor(&temp, tokens);

	return 1;
}

static int parse_str_attr(struct cursor *tokens,
			  struct attribute *attr,
			  const char *sym,
			  enum attribute_type type,
			  enum token_type tok_type)
{
	struct cursor temp;
	struct tok_str str;
	int ok;

	assert(tok_type == T_NUMBER || tok_type == T_SYMBOL || tok_type == T_STRING);

	copy_cursor(tokens, &temp);

	ok = parse_symbol(&temp, sym);
	if (!ok) return 0;

	ok = parse_stringy_token(&temp, &str, tok_type);
	if (!ok) return 0;

	attr->data.str.ptr = (char*)str.data;
	attr->data.str.len = str.len;
	attr->type = type;

	tokdebug("attribute %s %.*s\n", sym, str.len, str.data);

	copy_cursor(&temp, tokens);

	return 1;
}

static int parse_size(struct cursor *tokens, struct attribute *attr)
{
	struct cursor temp;
	struct tok_str str;
	int ok;

	copy_cursor(tokens, &temp);

	ok = pull_symbol_token(&temp, &str);
	if (!ok) return 0;

	if (symbol_eq(&str, "height", 6)) {
		attr->type = A_HEIGHT;
	} else if (symbol_eq(&str, "width", 5)) {
		attr->type = A_WIDTH;
	} else if (symbol_eq(&str, "depth", 5)) {
		attr->type = A_DEPTH;
	}

	ok = parse_number(&temp, &attr->data.number);
	if (!ok) return 0;

	tokdebug("attribute %s %d\n",
		 attr_type_str(attr->type),
		 attr->data.number.integer);

	copy_cursor(&temp, tokens);

	return 1;
}

int cell_name(struct cursor *attributes, struct cell *cell, const char** name, int *len)
{
	int i;
	struct attribute *attr;
	*len = 0;
	*name = "";

	for (i = 0; i < cell->n_attributes; i++) {
		attr = get_attr(attributes, cell->attributes[i]);
		if (attr->type == A_NAME) {
			*name = attr->data.str.ptr;
			*len = attr->data.str.len;
			return 1;
		}
	}

	return 0;
}

static int parse_attribute(struct cursor *tokens, struct attribute *attr)
{
	int ok;
	struct cursor temp;

	copy_cursor(tokens, &temp);

	ok = parse_open(&temp);
	if (!ok) return 0;

	ok = parse_shape(&temp, attr);
	if (ok) goto close;

	ok = parse_str_attr(&temp, attr, "id", A_ID, T_SYMBOL);
	if (ok) goto close;

	ok = parse_str_attr(&temp, attr, "name", A_NAME, T_STRING);
	if (ok) {
		goto close;
	}

	ok = parse_str_attr(&temp, attr, "material", A_MATERIAL, T_SYMBOL);
	if (ok) goto close;

	/* TODO: parse multiple conditions */
	ok = parse_str_attr(&temp, attr, "condition", A_CONDITION, T_SYMBOL);
	if (ok) goto close;

	ok = parse_str_attr(&temp, attr, "location", A_LOCATION, T_SYMBOL);
	if (ok) goto close;

	ok = parse_size(&temp, attr);
	if (ok) goto close;

	return 0;
 close:
	ok = parse_close(&temp);
	if (!ok) return 0;

	copy_cursor(&temp, tokens);

	return 1;
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


static int push_cell(struct cursor *cells, struct cell *cell, u16 *cell_index)
{
	int index;
	int ok;

	index = cursor_index(cells, sizeof(*cell));

	tokdebug("push_cell %d (%zu) %s\n", index, cells->p - cells->start, cell_type_str(cell->type));

	if (index > 0xFFFF) {
		/* TODO: actual error message here */
		printf("push_cell_child overflow\n");
		return 0;
	}

	ok = push_data(cells, (u8*)cell, sizeof(*cell));
	if (!ok) return 0;

	if (cell_index)
		*cell_index = index;

	return 1;
}

static void copy_parser(struct parser *from, struct parser *to)
{
	to->tokens = from->tokens;
	to->cells = from->cells;
	to->attributes = from->attributes;
}

static int push_cell_child(struct cell *parent, u16 child_ind)
{
	int ok;
	struct cursor child_inds;

	make_cursor((u8*)parent->children,
		    (u8*)parent->children + sizeof(parent->children),
		    &child_inds);

	child_inds.p += parent->n_children * sizeof(parent->children[0]);

	ok = push_u16(&child_inds, child_ind);
	if (!ok) return 0;

	parent->n_children++;

	return 1;
}

const char *object_type_str(enum object_type type)
{
	switch (type) {
	case O_DOOR: return "door";
	case O_TABLE: return "table";
	case O_LIGHT: return "light";
	}

	return "unknown";
}

const char *cell_type_str(enum cell_type type)
{
	switch (type) {
	case C_GROUP: return "group";
	case C_SPACE: return "space";
	case C_OBJECT: return "object";
	case C_ROOM: return "room";
	}

	return "unknown";
}

static int parse_cell_attrs(struct parser *parser, u16 *index, struct cell *cell)
{
	struct cursor cell_attr_inds;
	struct cell *child_cell;
	u16 child_cell_index;
	int attr_inds[2] = {0};
	int i, ok;

	make_cursor((u8*)cell->attributes,
		    (u8*)cell->attributes + sizeof(cell->attributes),
		    &cell_attr_inds);

	cell_attr_inds.p += cell->n_attributes * sizeof(cell->attributes[0]);

	/* 0 attributes returns 1, 1 attrs returns 2, etc
	   0 is a real error, an attribute push overflow */
	ok = parse_attributes(parser->tokens, parser->attributes, attr_inds);
	if (!ok) return 0;

	tokdebug("parse_attributes %d\n", ok);

	for (i = attr_inds[0]; i <= attr_inds[1]; i++) {
		ok = push_int(&cell_attr_inds, i);
		cell->n_attributes++;
		if (!ok) return 0;
	}

	/* Optional child cell */
	tokdebug("optional child cell in parse_cell_attrs\n");
	ok = parse_cell(parser, &child_cell_index);
	if (ok) {
		child_cell = get_cell(parser->cells, child_cell_index);
		if (!child_cell) return 0;
		tokdebug("parse_cell_attrs push child cell\n");
		ok = push_cell_child(cell, child_cell_index);
		if (!ok) return 0;

	}
	else {
		tokdebug("no child cells found\n");
	}

	ok = push_cell(parser->cells, cell, index);
	if (!ok) return 0;

	return 1;
}

static int parse_cell_by_name(struct parser *parser,
			      u16 *index,
			      const char *name,
			      enum cell_type type)
{
	int ok;
	struct cursor temp;
	struct parser backtracked;
	struct cell cell;
	u16 ind;

	init_cell(&cell);
	copy_cursor(parser->tokens, &temp);
	copy_parser(parser, &backtracked);
	backtracked.tokens = &temp;

	cell.type = type;

	ok = parse_symbol(&temp, name);
	if (!ok) return 0;

	ok = parse_cell_attrs(&backtracked, &ind, &cell);
	if (!ok) return 0;

	if (index)
		*index = ind;

	copy_cursor(&temp, parser->tokens);

	return 1;
}


static int parse_room(struct parser *parser, u16 *index)
{
	return parse_cell_by_name(parser, index, "room", C_ROOM);
}

static int parse_group(struct parser *parser, u16 *index)
{
	int ok;
	int ncells = 0;
	u16 child_ind;

	struct parser backtracked;
	struct cursor temp;
	struct cell group;
	struct cell *child_cell;

	init_cell(&group);

	copy_cursor(parser->tokens, &temp);
	copy_parser(parser, &backtracked);
	backtracked.tokens = &temp;

	ok = parse_symbol(&temp, "group");
	if (!ok) return 0;

	while (1) {
		ok = parse_cell(&backtracked, &child_ind);
		if (!ok) break;

		child_cell = get_cell(parser->cells, child_ind);
		if (child_cell == NULL) {
			printf("UNUSUAL: group get_cell was NULL\n");
			return 0;
		}

		tokdebug("group child cell type %s\n", cell_type_str(child_cell->type));
		ok = push_cell_child(&group, child_ind);
		if (!ok) return 0;

		ncells++;
	}

	tokdebug("parse_group cells %d\n", ncells);

	if (ncells == 0)
		return 0;

	group.type = C_GROUP;

	ok = push_cell(parser->cells, &group, index);
	if (!ok) return 0;

	copy_cursor(&temp, parser->tokens);

	return ncells;
}

struct object_def {
	const char *name;
	enum object_type type;
};

static struct object_def object_defs[] = {
	{"table", O_TABLE},
	{"door", O_DOOR},
	{"light", O_LIGHT},
};

static int parse_object(struct parser *parser, u16 *index)
{
	int ok, i;
	struct cursor temp;
	struct parser backtracked;
	struct tok_str str;
	struct object_def *def;
	struct cell cell;
	u16 ind;

	init_cell(&cell);
	cell.type = C_OBJECT;

	copy_cursor(parser->tokens, &temp);
	copy_parser(parser, &backtracked);
	backtracked.tokens = &temp;

	ok = pull_symbol_token(&temp, &str);
	if (!ok) return 0;

	for (i = 0; i < ARRAY_SIZE(object_defs); i++) {
		def = &object_defs[i];

		if (symbol_eq(&str, def->name, strlen(def->name))) {
			cell.obj_type = def->type;
			break;
		}
	}

	ok = parse_cell_attrs(&backtracked, &ind, &cell);
	if (!ok) return 0;

	assert(ind < 10);
	if (index)
		*index = ind;

	copy_cursor(&temp, parser->tokens);

	return 1;
}

int parse_cell(struct parser *parser, u16 *index)
{
	int ok;
	struct cursor temp;
	struct parser backtracked;

	/* mostly needed for parse_open and parse_close */
	copy_cursor(parser->tokens, &temp);
	copy_parser(parser, &backtracked);
	backtracked.tokens = &temp;

	ok = parse_open(&temp);
	if (!ok) {
		tokdebug("parse_open failed in parse_cell\n");
		return 0;
	}

	ok = parse_group(&backtracked, index);
	if (ok) {
		tokdebug("got parse_group\n");
		goto close;
	}

	ok = parse_room(&backtracked, index);
	if (ok) {
		tokdebug("got parse_room\n");
		goto close;
	}

	ok = parse_object(&backtracked, index);
	if (ok) goto close;

	return 0;
close:
	ok = parse_close(&temp);
	if (!ok) return 0;

	copy_cursor(&temp, parser->tokens);

	return 1;
}
