
#include "util.h"
#include "parse.h"
#include "io.h"

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


#ifdef DEBUG
#endif
static const char *attr_type_str(enum attribute_type type)
{
	switch (type) {
	case A_CONDITION: return "condition";
	case A_DEPTH: return "depth";
	case A_HEIGHT: return "height";
	case A_ID: return "id";
	case A_LOCATION: return "location";
	case A_MATERIAL: return "material";
	case A_COLOR: return "color";
	case A_NAME: return "name";
	case A_SHAPE: return "shape";
	case A_TYPE: return "type";
	case A_WIDTH: return "width";
	case A_STATE: return "state";
	case A_DATA: return "data";
	}

	return "unknown";
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

static void copy_token_cursor(struct token_cursor *src, struct token_cursor *dest)
{
	copy_cursor(&src->c, &dest->c);
	dest->err = src->err;
	memcpy(&dest->err_data, &src->err_data, sizeof(src->err_data));
}

static void init_token_cursor(struct token_cursor *cursor)
{
	cursor->err = TE_OK;
	memset(&cursor->err_data, 0, sizeof(cursor->err_data));
}

struct attribute *get_attr(struct cursor *attributes, int index)
{
	return (struct attribute*)index_cursor(attributes, index,
					       sizeof(struct attribute));
}

/*
*/
static const char *shape_str(enum shape shape)
{
	switch (shape) {
	case SHAPE_RECTANGLE: return "rectangle";
	case SHAPE_CIRCLE: return "circle";
	case SHAPE_SQUARE: return "square";
	}

	return "unknown";
}


static void print_attribute(struct attribute *attr)
{
	printf("%s ", attr_type_str(attr->type));

	switch (attr->type) {
	case A_NAME:
		printf("%.*s ", attr->data.str.len, attr->data.str.ptr);
	        break;
	case A_SHAPE:
		printf("%s ", shape_str(attr->data.shape));
		break;
	default:
		break;
	}

}

static void print_attributes(struct cursor *attributes, struct cell *cell)
{
	int i;
	struct attribute *attr;

	printf("%d attrs: ", cell->n_attributes);
	for (i = 0; i < cell->n_attributes; i++) {
		attr = get_attr(attributes, cell->attributes[i]);
		assert(attr);
		printf("[%d]", cell->attributes[i]);
		print_attribute(attr);
	}
}

void print_cell(struct cursor *attributes, struct cell *cell)
{
	const char *name;
	int name_len;

	if (cell->type == C_GROUP) {
		printf("---\n");
		return;
	}

	cell_attr_str(attributes, cell, &name, &name_len, A_NAME);

	printf("%.*s%s%s ", name_len, name, name_len > 0?" ":"",
	       cell->type == C_OBJECT
	       ? object_type_str(cell->obj_type)
	       : cell_type_str(cell->type));

	//print_attributes(attributes, cell);
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

void print_token_error(struct token_cursor *cursor)
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


#ifdef DEBUG
static void print_spaces(int n)
{
	int i;
	for (i = 0; i < n; i++)
		putchar(' ');
}
#endif

static int push_token_data(struct token_cursor *tokens,
			   enum token_type token,
			   void *token_data, int token_data_size)
{
	static int depth = 0;
#ifdef DEBUG
	struct tok_str *str;
#endif
	if (!cursor_push_byte(&tokens->c, token))
		return 0;

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
		if (!cursor_push(&tokens->c, token_data, token_data_size)) {
			printf("hmm? %d\n", token_data_size);
			cursor_print_around(&tokens->c, 10);
			return 0;
		}
#ifdef DEBUG
		printf("\n");
#endif
		break;
	}


	return 1;
}


static int push_token(struct token_cursor *tokens, enum token_type token)
{
	return push_token_data(tokens, token, NULL, 0);
}

static int push_symbol(struct token_cursor *tokens, struct tok_str symbol)
{
	return push_token_data(tokens, T_SYMBOL, &symbol, sizeof(symbol));
}

static int push_string(struct token_cursor *tokens, struct tok_str str)
{
	return push_token_data(tokens, T_STRING, &str, sizeof(str));
}

static int push_number(struct token_cursor *tokens, struct tok_str str)
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

static int pull_number(struct token_cursor *cursor, u8 **start)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct cursor temp;

	*start = temp.p = cursor->c.p;
	temp.end = cursor->c.end;

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

	cursor->c.p = temp.p-1;
	cursor->err = TE_OK;

	/* remove the first counted quote since this was not pushed */
	return chars;
}

static int pull_string(struct token_cursor *cursor, u8 **start, int *len)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct token_cursor temp;

	copy_token_cursor(cursor, &temp);

	while (1) {
		if (chars == 0)
			*start = temp.c.p+1;

		ok = pull_escaped_char(&temp.c, &c);
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

	copy_token_cursor(&temp, cursor);

	/* remove the first counted quote since this was not pushed */
	*len = temp.c.p - *start - 1;
	return 1;
}

static int pull_symbol(struct token_cursor *cursor, u8 **start)
{
	int ok = 1;
	int chars = 0;
	u8 c;

	struct token_cursor temp;

	copy_token_cursor(cursor, &temp);

	*start = temp.c.p;

	while (1) {
		ok = pull_byte(&temp.c, &c);
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

	temp.c.p--;
	copy_token_cursor(&temp, cursor);

	return chars;
}

static void init_cell(struct cell *cell)
{
	memset(cell, 0, sizeof(*cell));
}

static int read_and_push_atom(struct token_cursor *cursor, struct token_cursor *tokens)
{
	struct tok_str str;
	u8 *start;
	int ok, len;

	ok = pull_symbol(cursor, &start);
	if (ok) {
		str.len  = ok;
		str.data = start;
		if (!push_symbol(tokens, str)) {
			cursor_print_around(&tokens->c, 10);
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

	start = cursor->c.p;
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

int tokenize_cells(u8 *buf, int buf_size, struct token_cursor *tokens)
{
	enum tok_state state;
	struct token_cursor cursor;
	/* u8 *start = buf; */
	u8 *token_buf = tokens->c.p;
	u8 c;
	int ok;

	cursor.c.p = buf;
	cursor.c.end = buf + buf_size;

	state = TS_OPEN;

	while (cursor.c.p < cursor.c.end) {
		ok = pull_byte(&cursor.c, &c);
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

			cursor.c.p--;
			/* printf("\nat %c (%ld) before reading atom\n", *cursor.p, cursor.p - start); */
			ok = read_and_push_atom(&cursor, tokens);
			if (!ok) {
				print_token_error(&cursor);
				return 0;
			}

		}
	}

	/* just seal the buffer now since we won't be adding to it */
	tokens->c.end = tokens->c.p;
	tokens->c.p = token_buf;

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
		ok = cursor_pull(tokens, (void*)&token->str,
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

static int pull_token(struct token_cursor *tokens,
		      union token *token,
		      enum token_type expected_type)
{
	struct token_cursor temp;
	enum token_type type;
	int ok;

	copy_token_cursor(tokens, &temp);

	ok = pull_token_type(&temp.c, &type);
	if (!ok) return 0;

	if (type != expected_type) {
		tokens->err = TE_UNEXPECTED_TOKEN;
		tokens->err_data.lex.expected = expected_type;
		tokens->err_data.lex.got = type;
		tokens->err_data.pos = cursor_count(&temp.c, 1);
		return 0;
	}

	ok = pull_token_data(&temp.c, token, type);
	if (!ok) {
		return 0;
	}

	copy_token_cursor(&temp, tokens);

	return 1;
}

#ifdef DEBUG
/*
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


static void print_current_token(struct token_cursor *tokens)
{
	struct token_cursor temp;
	enum token_type type;
	union token token;
	int ok;

	copy_token_cursor(tokens, &temp);

	ok = pull_token_type(&temp.c, &type);
	if (!ok) {
		printf("could not peek token\n");
		return;
	}

	printf("current token: %s ", token_type_str(type));

	ok = pull_token_data(&temp.c, &token, type);
	if (!ok) {
		printf("[could not peek token data]\n");
		return;
	}

	print_token_data(&token, type);
	printf("\n");
}
*/
#endif

/*
 *  PARSING
 */


static int parse_open(struct token_cursor *tokens)
{
	return pull_token(tokens, NULL, T_OPEN);
}

static int parse_close(struct token_cursor *tokens)
{
	return pull_token(tokens, NULL, T_CLOSE);
}

static int parse_stringy_token(struct token_cursor *tokens,
			       struct tok_str *str,
			       enum token_type type)
{
	union token token;

	if (!pull_token(tokens, &token, type))
		return 0;

	str->data = token.str.data;
	str->len = token.str.len;

	return 1;
}


static int pull_symbol_token(struct token_cursor *tokens, struct tok_str *str)
{
	return parse_stringy_token(tokens, str, T_SYMBOL);
}

static int pull_number_token(struct token_cursor *tokens, struct tok_str *str)
{
	return parse_stringy_token(tokens, str, T_NUMBER);
}

static int parse_number(struct token_cursor *tokens, union number *number)
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


struct cell *get_cell(struct cursor *cells, int index)
{
	return (struct cell*)index_cursor(cells, index,
					  sizeof(struct cell));
}


static int symbol_eq(struct tok_str *a, const char *b, int b_len)
{
	return memeq(a->data, a->len, (char*)b, b_len);
}

static int parse_symbol(struct token_cursor *tokens, const char *match)
{
	struct tok_str str;

	if (!pull_symbol_token(tokens, &str))
		return 0;

	if (!symbol_eq(&str, match, strlen(match)))
		return 0;

	return 1;
}

static int parse_shape(struct token_cursor *tokens, struct attribute *attr)
{
	struct token_cursor temp;
	struct tok_str str;
	int ok;

	copy_token_cursor(tokens, &temp);

	ok = parse_symbol(&temp, "shape");
	if (!ok) return 0;

	attr->type = A_SHAPE;

	ok = pull_symbol_token(&temp, &str);
	if (!ok) return 0;

	if (symbol_eq(&str, "rectangle", 9)) {
		attr->data.shape = SHAPE_RECTANGLE;
	} else if (symbol_eq(&str, "circle", 6)) {
		attr->data.shape = SHAPE_CIRCLE;
	} else if (symbol_eq(&str, "square", 6)) {
		attr->data.shape = SHAPE_SQUARE;
	} else {
		tokens->err = TE_UNEXPECTED_SYMBOL;
		tokens->err_data.symbol.expected.data = (u8*)"rectangle";
		tokens->err_data.symbol.expected.len = 9;
		tokens->err_data.symbol.got.data = str.data;
		tokens->err_data.symbol.got.len = str.len;
	}

	copy_token_cursor(&temp, tokens);

	return 1;
}

static int parse_str_attr(struct token_cursor *tokens,
			  struct attribute *attr,
			  const char *sym,
			  enum attribute_type type,
			  enum token_type tok_type)
{
	struct token_cursor temp;
	struct tok_str str;
	struct bufstr *bufstr;

	assert(tok_type == T_NUMBER || tok_type == T_SYMBOL || tok_type == T_STRING);

	copy_token_cursor(tokens, &temp);

	if (sym == NULL) {
		if (!pull_symbol_token(&temp, &str))
			return 0;

		attr->data.data_attr.sym.ptr = (char*)str.data;
		attr->data.data_attr.sym.len = str.len;

		bufstr = &attr->data.data_attr.str;
	} else {
		if (!parse_symbol(&temp, sym))
			return 0;
		bufstr = &attr->data.str;
	}

	if (!parse_stringy_token(&temp, &str, tok_type))
		return 0;

	bufstr->ptr = (char*)str.data;
	bufstr->len = str.len;
	attr->type = type;

#ifdef DEBUG
	if (sym == NULL)
		tokdebug("attribute %.*s %.*s\n",
				attr->data.data_attr.sym.len,
				attr->data.data_attr.sym.ptr,
				str.len,
				str.data);
	else
		tokdebug("attribute %s %.*s\n", sym, str.len, str.data);
#endif

	copy_token_cursor(&temp, tokens);

	return 1;
}

static int parse_size(struct token_cursor *tokens, struct attribute *attr)
{
	struct token_cursor temp;
	struct tok_str str;
	int ok;

	copy_token_cursor(tokens, &temp);

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

	copy_token_cursor(&temp, tokens);

	return 1;
}

static struct bufstr *attr_bufstr(struct attribute *attr)
{
	if (attr->type == A_DATA)
		return &attr->data.data_attr.str;
	return &attr->data.str;
}

int cell_attr_str(struct cursor *attributes, struct cell *cell,
		const char** name, int *len, enum attribute_type type)
{
	int i;
	struct attribute *attr;
	struct bufstr *bufstr;
	*len = 0;
	*name = "";

	for (i = 0; i < cell->n_attributes; i++) {
		attr = get_attr(attributes, cell->attributes[i]);
		if (attr->type == type) {
			bufstr = attr_bufstr(attr);
			*name = bufstr->ptr;
			*len = bufstr->len;
			return 1;
		}
	}

	return 0;
}

const char *cell_name(struct cursor *attributes, struct cell *cell, int *len)
{
	const char *name = NULL;
	if (!cell_attr_str(attributes, cell, &name, len, A_NAME))
		return NULL;
	return name;
}

static int parse_attribute(struct token_cursor *tokens, struct attribute *attr)
{
	int ok;
	struct token_cursor temp;

	copy_token_cursor(tokens, &temp);

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

	ok = parse_str_attr(&temp, attr, "material", A_MATERIAL, T_STRING);
	if (ok) goto close;

	ok = parse_str_attr(&temp, attr, "color", A_COLOR, T_STRING);
	if (ok) goto close;

	/* TODO: parse multiple conditions */
	ok = parse_str_attr(&temp, attr, "condition", A_CONDITION, T_STRING);
	if (ok) goto close;

	ok = parse_str_attr(&temp, attr, "location", A_LOCATION, T_SYMBOL);
	if (ok) goto close;

	ok = parse_str_attr(&temp, attr, "state", A_STATE, T_SYMBOL);
	if (ok) goto close;

	ok = parse_str_attr(&temp, attr, NULL, A_DATA, T_STRING);
	if (ok) goto close;

	ok = parse_size(&temp, attr);
	if (ok) goto close;

	return 0;
 close:
	ok = parse_close(&temp);
	if (!ok) return 0;

	copy_token_cursor(&temp, tokens);

	return 1;
}

static int parse_attributes(struct token_cursor *tokens,
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

		index = cursor_count(attributes, sizeof(attr));
		ok = cursor_push(attributes, (u8*)&attr, sizeof(attr));

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


static int push_cell(struct cursor *cells, struct cell *cell, int *cell_index)
{
	int index;
	int ok;

	index = cursor_count(cells, sizeof(*cell));

	tokdebug("push_cell %d (%zu) %s\n", index, cells->p - cells->start, cell_type_str(cell->type));

	if (index > 0xFFFF) {
		/* TODO: actual error message here */
		printf("push_cell_child overflow\n");
		return 0;
	}

	ok = cursor_push(cells, (u8*)cell, sizeof(*cell));
	if (!ok) return 0;

	if (cell_index)
		*cell_index = index;

	return 1;
}

static void copy_parser(struct parser *from, struct parser *to)
{
	copy_token_cursor(&from->tokens, &to->tokens);
	copy_cursor(&from->cells, &to->cells);
	copy_cursor(&from->attributes, &to->attributes);
}

static int push_cell_child(struct cell *parent, int child_ind)
{
	int ok;
	struct cursor child_inds;

	make_cursor((u8*)parent->children,
		    (u8*)parent->children + sizeof(parent->children),
		    &child_inds);

	child_inds.p += parent->n_children * sizeof(parent->children[0]);

	ok = cursor_push_u16(&child_inds, child_ind);
	if (!ok) return 0;

	parent->n_children++;

	return 1;
}

const char *object_type_str(enum object_type type)
{
	switch (type) {
	case O_DOOR: return "door";
	case O_TABLE: return "table";
	case O_CHAIR: return "chair";
	case O_LIGHT: return "light";
	case O_OBJECT: return "";
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

static int parse_cell_attrs(struct parser *parser, int *index, struct cell *cell)
{
	struct cursor cell_attr_inds;
	struct cell *child_cell;
	int child_cell_index;
	int attr_inds[2] = {0};
	int i, ok;

	make_cursor((u8*)cell->attributes,
		    (u8*)cell->attributes + sizeof(cell->attributes),
		    &cell_attr_inds);

	cell_attr_inds.p += cell->n_attributes * sizeof(cell->attributes[0]);

	/* 0 attributes returns 1, 1 attrs returns 2, etc
	   0 is a real error, an attribute push overflow */
	ok = parse_attributes(&parser->tokens, &parser->attributes, attr_inds);
	if (!ok) return 0;

	tokdebug("parse_attributes %d\n", ok);

	for (i = attr_inds[0]; i <= attr_inds[1]; i++) {
		ok = cursor_push_u16(&cell_attr_inds, i);
		if (!ok) return 0;
		cell->n_attributes++;
	}

	/* Optional child cell */
	tokdebug("optional child cell in parse_cell_attrs\n");
	ok = parse_cell(parser, &child_cell_index);
	if (ok) {
		if (!(child_cell = get_cell(&parser->cells, child_cell_index)))
			return 0;
		tokdebug("parse_cell_attrs push child cell\n");
		if (!push_cell_child(cell, child_cell_index))
			return 0;

	}
	else {
		tokdebug("no child cells found\n");
	}

	ok = push_cell(&parser->cells, cell, index);
	if (!ok) return 0;

	return 1;
}

static int parse_cell_by_name(struct parser *parser,
			      int *index,
			      const char *name,
			      enum cell_type type)
{
	int ok;
	struct parser backtracked;
	struct cell cell;
	int ind;

	init_cell(&cell);

	copy_parser(parser, &backtracked);

	cell.type = type;

	ok = parse_symbol(&backtracked.tokens, name);
	if (!ok) return 0;

	ok = parse_cell_attrs(&backtracked, &ind, &cell);
	if (!ok) return 0;

	if (index)
		*index = ind;

	copy_parser(&backtracked, parser);

	return 1;
}

static int parse_space(struct parser *parser, int *index)
{
	return parse_cell_by_name(parser, index, "space", C_SPACE);
}

static int parse_room(struct parser *parser, int *index)
{
	return parse_cell_by_name(parser, index, "room", C_ROOM);
}

static int parse_group(struct parser *parser, int *index)
{
	int ncells = 0;
	int child_ind;

	struct parser backtracked;
	struct cell group;
	struct cell *child_cell;

	init_cell(&group);

	copy_parser(parser, &backtracked);

	if (!parse_symbol(&backtracked.tokens, "group"))
		return 0;

	while (1) {
		if (!parse_cell(&backtracked, &child_ind))
			break;

		child_cell = get_cell(&backtracked.cells, child_ind);
		if (child_cell == NULL) {
			printf("UNUSUAL: group get_cell was NULL\n");
			return 0;
		}

		tokdebug("group child cell type %s\n", cell_type_str(child_cell->type));
		if (!push_cell_child(&group, child_ind))
			return 0;

		ncells++;
	}

	tokdebug("parse_group cells %d\n", ncells);

	if (ncells == 0)
		return 0;

	group.type = C_GROUP;

	if (!push_cell(&backtracked.cells, &group, index))
		return 0;

	copy_parser(&backtracked, parser);

	return ncells;
}

struct object_def {
	const char *name;
	enum object_type type;
};

static struct object_def object_defs[] = {
	{"table", O_TABLE},
	{"chair", O_CHAIR},
	{"door", O_DOOR},
	{"light", O_LIGHT},
	{"obj", O_OBJECT},
};

static int parse_object(struct parser *parser, int *index)
{
	int i;
	struct parser backtracked;
	struct tok_str str;
	struct object_def *def;
	struct cell cell;
	int ind;

	init_cell(&cell);
	cell.type = C_OBJECT;

	copy_parser(parser, &backtracked);

	if (!pull_symbol_token(&backtracked.tokens, &str))
		return 0;

	for (i = 0; i < ARRAY_SIZE(object_defs); i++) {
		def = &object_defs[i];

		if (symbol_eq(&str, def->name, strlen(def->name))) {
			cell.obj_type = def->type;
			break;
		}
	}

	if (!parse_cell_attrs(&backtracked, &ind, &cell))
		return 0;

	if (index)
		*index = ind;

	copy_parser(&backtracked, parser);

	return 1;
}

int parse_cell(struct parser *parser, int *index)
{
	int ok;
	struct parser backtracked;

	/* mostly needed for parse_open and parse_close */
	copy_parser(parser, &backtracked);

	ok = parse_open(&backtracked.tokens);
	if (!ok) {
		tokdebug("parse_open failed in parse_cell\n");
		return 0;
	}

	ok = parse_group(&backtracked, index);
	if (ok) {
		tokdebug("got parse_group\n");
		goto close;
	}

	/* print_current_token(&backtracked.tokens); */

	ok = parse_room(&backtracked, index);
	if (ok) {
		tokdebug("got parse_room\n");
		goto close;
	}

	ok = parse_space(&backtracked, index);
	if (ok) {
		tokdebug("got parse_space\n");
		goto close;
	}

	ok = parse_object(&backtracked, index);
	if (ok) goto close;

	return 0;
close:
	ok = parse_close(&backtracked.tokens);
	if (!ok) return 0;

	copy_parser(&backtracked, parser);

	return 1;
}


int init_parser(struct parser *parser)
{
	struct cursor mem;
	u8 *pmem;
	int ok;

	int attrs_size = sizeof(struct attribute) * 1024;
	int tokens_size = 2048*32;
	int cells_size = sizeof(struct cell) * 1024;
	int memsize = attrs_size + tokens_size + cells_size;

	if (!(pmem = calloc(1, memsize))) {
		return 0;
	}

	make_cursor(pmem, pmem + memsize, &mem);

	ok =
		cursor_slice(&mem, &parser->cells, cells_size) &&
		cursor_slice(&mem, &parser->attributes, attrs_size) &&
		cursor_slice(&mem, &parser->tokens.c, tokens_size);
	assert(ok);

	init_token_cursor(&parser->tokens);

	return 1;
}

int free_parser(struct parser *parser)
{
	free(parser->cells.start);

	return 1;
}

int parse_buffer(struct parser *parser, u8 *file_buf, int len, int *root)
{
	int ok;

	ok = tokenize_cells(file_buf, len, &parser->tokens);

	if (!ok) {
		printf("failed to tokenize\n");
		return 0;
	}

	ok = parse_cell(parser, root);
	if (!ok) {
		print_token_error(&parser->tokens);
		return 0;
	}

	return 1;
}


int parse_file(struct parser *parser, const char *filename, int *root, u8 *buf,
		u32 bufsize)
{
	int count, ok;

	ok = read_file(filename, buf, bufsize, &count);

	if (!ok) {
		printf("failed to load '%s'\n", filename);
		return 0;
	}

	ok = parse_buffer(parser, buf, count, root);
	return ok;
}

