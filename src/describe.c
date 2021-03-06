
#include "describe.h"
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#define ADJ_PUSHED 1
#define ADJ_NOT_PUSHED 2

/* various functions used to describe the scene */

static int push_sized_word(struct cursor *strs, const char *str, int len)
{
	int ok;

	if (strs->p-1 >= strs->start && !isspace(*(strs->p-1))) {
		ok = cursor_push_str(strs, " ");
		if (!ok) return 0;
	}

	ok = push_sized_str(strs, str, len);
	if (!ok) return 0;

	return 1;
}

static int push_word(struct cursor *strs, const char *str)
{
	return push_sized_word(strs, str, strlen(str));
}

static int push_adjective(struct cursor *strs, struct attribute *attr)
{
	int ok;

	switch (attr->type) {
	case A_CONDITION:
		ok = cursor_push_str(strs, " ");
		if (!ok) return 0;
		ok = push_sized_str(strs, attr->data.str.ptr,
				    attr->data.str.len);
		if (!ok) return 0;
		return ADJ_PUSHED;
	default:
		break;
	}

	return ADJ_NOT_PUSHED;
}

static int is_adjective(struct attribute *attr)
{
	return attr->type == A_CONDITION;
}

static int count_adjectives(struct describe *desc)
{
	struct attribute *attr;
	int count;
	int i;

	for (i = 0, count = 0; i < desc->cell->n_attributes; i++) {
		attr = get_attr(&desc->parsed->attributes,
				desc->cell->attributes[i]);
		assert(attr);

		if (is_adjective(attr))
			count++;
	}

	return count;
}

static int push_adjectives(struct describe *desc)
{
	struct attribute *attr;
	int i, ok, adjs, adj_count;

	adj_count = count_adjectives(desc);

	for (i = 0, adjs = 0; i < desc->cell->n_attributes; i++) {
		attr = get_attr(&desc->parsed->attributes,
				desc->cell->attributes[i]);
		assert(attr);

		if (!is_adjective(attr))
			continue;

		if (adjs > 0) {
			if (adjs == adj_count-1) {
				ok = push_word(desc->strs, "and");
				if (!ok) return 0;
			}
			else if (adjs != adj_count-1) {
				ok = cursor_push_str(desc->strs, ",");
				if (!ok) return 0;
			}

		}

		ok = push_adjective(desc->strs, attr);
		if (ok == ADJ_PUSHED)
			adjs++;
	}

	return 1;
}

static int find_attr(struct cursor *attrs, struct cell *cell,
		     enum attribute_type type, struct attribute **attr)
{
	int i;

	for (i = 0; i < cell->n_attributes; i++) {
		*attr = get_attr(attrs, cell->attributes[i]);
		assert(*attr);

		if ((*attr)->type == type)
			return 1;
	}

	return 0;
}

static int push_made_of(struct describe *desc)
{
	struct attribute *attr;
	int ok;

	ok = find_attr(&desc->parsed->attributes, desc->cell,
		       A_MATERIAL, &attr);
	if (!ok) return 2;

	ok = push_word(desc->strs, "made of");
	if (!ok) return 0;

	ok = push_sized_word(desc->strs, attr->data.str.ptr,
			       attr->data.str.len);
	if (!ok) return 0;
	return 1;
}

static int push_named(struct describe *desc)
{
	const char *name;
	int name_len;
	int ok;

	cell_name(&desc->parsed->attributes, desc->cell, &name, &name_len);

	if (name_len == 0)
		return 1;

	ok = push_word(desc->strs, "named");
	if (!ok) return 0;

	ok = push_sized_word(desc->strs, name, name_len);
	if (!ok) return 0;

	return 1;
}

static int push_shape(struct describe *desc)
{
	struct attribute *attr;
	int ok;

	ok = find_attr(&desc->parsed->attributes, desc->cell, A_SHAPE, &attr);
	if (!ok) return 2;

	switch (attr->data.shape) {
	case SHAPE_RECTANGLE:
		push_word(desc->strs, "rectangular");
		break;
	case SHAPE_CIRCLE:
		push_word(desc->strs, "circular");
		break;
	case SHAPE_SQUARE:
		push_word(desc->strs, "square");
		break;
	}

	return 1;
}

static int describe_room(struct describe *desc)
{
	int ok;

	/* TODO: temp buffers for determining a(n) things */
	ok = cursor_push_str(desc->strs, "There is a(n)");
	if (!ok) return 0;

	ok = push_adjectives(desc);
	if (!ok) return 0;

	ok = push_shape(desc);
	if (!ok) return 0;

	ok = push_word(desc->strs, "room");
	if (!ok) return 0;

	ok = push_made_of(desc);
	if (!ok) return 0;

	ok = push_named(desc);
	if (!ok) return 0;

	return 1;
}

static int describe_amount(struct describe *desc, int nobjs)
{
	int ok;

	if (nobjs == 1) {
		ok = push_word(desc->strs, "a single");
		if (!ok) return 0;
	} else if (nobjs == 2) {
		ok = push_word(desc->strs, "a couple");
		if (!ok) return 0;
	} else if (nobjs == 3) {
		ok = push_word(desc->strs, "three");
		if (!ok) return 0;
	} else if (nobjs == 4) {
		ok = push_word(desc->strs, "four");
		if (!ok) return 0;
	} else if (nobjs == 5) {
		ok = push_word(desc->strs, "five");
		if (!ok) return 0;
	} else {
		ok = push_word(desc->strs, "many");
		if (!ok) return 0;
	}

	return 1;
}

static int describe_object_name(struct cursor *strs, struct cursor *attrs, struct cell *cell)
{
	int ok;
	const char *name;
	int name_len;

	cell_name(attrs, cell, &name, &name_len);
	if (name_len > 0) {
		ok = push_sized_word(strs, name, name_len);
		if (!ok) return 0;
	}

	return push_word(strs, cell->type == C_OBJECT
			  ? object_type_str(cell->obj_type)
			  : cell_type_str(cell->type));
}

static int describe_group(struct describe *desc)
{
	int i, ok, nobjs;
	struct cell *cell;

	nobjs = desc->cell->n_children;

	ok = describe_amount(desc, nobjs);

	ok = push_word(desc->strs, "object");
	if (!ok) return 0;

	if (nobjs > 1) {
		ok = cursor_push_str(desc->strs, "s:");
		if (!ok) return 0;
	}
	else {
		cursor_push_str(desc->strs, ":");
		if (!ok) return 0;
	}

	ok = push_word(desc->strs, "a");
	if (!ok) return 0;

	for (i = 0; i < nobjs; i++) {
		cell = get_cell(&desc->parsed->cells,
				desc->cell->children[i]);
		assert(cell);

		if (i > 0) {
			if (i == nobjs-1) {
				ok = push_word(desc->strs, "and");
				if (!ok) return 0;
			}
			else if (i != nobjs-1) {
				ok = cursor_push_str(desc->strs, ",");
				if (!ok) return 0;
			}

		}

		ok = describe_object_name(desc->strs, &desc->parsed->attributes, cell);
		if (!ok) return 0;
	}

	return 1;
}

static int describe_object(struct describe *desc)
{
	(void)desc;
	return 0;
}

static int describe_space(struct describe *desc)
{
	(void)desc;
	return 0;
}

int describe_cell(struct cell *cell, struct parser *parsed, struct cursor *strbuf)
{
	struct describe desc;

	desc.cell = cell;
	desc.parsed = parsed;
	desc.strs = strbuf;

	switch (cell->type) {
	case C_ROOM:
		return describe_room(&desc);
	case C_GROUP:
		return describe_group(&desc);
	case C_OBJECT:
		return describe_object(&desc);
	case C_SPACE:
		return describe_space(&desc);
	}

	return 1;
}


int describe_cells(struct cell *cell, struct parser *parsed, struct cursor *strs, int max_depth, int depth)
{
	int ok;

	if (depth > max_depth)
		return 1;

	ok = describe_cell(cell, parsed, strs);
	if (!ok) return 0;

	ok = cursor_push_str(strs, ".\n");
	if (!ok) return 0;

	if (cell->n_children == 0)
		return 1;

	if (cell->type == C_ROOM || cell->type == C_SPACE) {
		ok = push_word(strs, "It contains");
		if (!ok) return 0;
	}

	/* TODO: for each cell ? for now we just care about the group */
	cell = get_cell(&parsed->cells, cell->children[0]);
	assert(cell);

	return describe_cells(cell, parsed, strs, max_depth, depth+1);
}


int describe(struct parser *parser, u16 root_cell)
{
	static char strbuf[2048];
	struct cursor strs;
	struct cell *cell;

	strbuf[0] = 0;

	cell = get_cell(&parser->cells, root_cell);

	make_cursor((u8*)strbuf, (u8*)strbuf + sizeof(strbuf), &strs);

	describe_cells(cell, parser, &strs, 10, 0);

	printf("\n\ndescription\n-----------\n\n%s\n", strbuf);

	return 1;
}
