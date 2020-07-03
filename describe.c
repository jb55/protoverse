
#include "describe.h"
#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#define ADJ_PUSHED 1
#define ADJ_NOT_PUSHED 2

/* various functions used to describe the scene */

struct describe {
	struct cell *cell;
	struct parser *parsed;
	struct cursor *strs;
};

static int push_sized_word(struct cursor *strs, const char *str, int len)
{
	int ok;

	if (strs->p-1 >= strs->start && !isspace(*(strs->p-1))) {
		ok = push_str(strs, " ");
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
		ok = push_str(strs, " ");
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
		attr = get_attr(desc->parsed->attributes,
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
		attr = get_attr(desc->parsed->attributes,
				desc->cell->attributes[i]);
		assert(attr);

		if (!is_adjective(attr))
			continue;

		if (adjs > 0) {
			if (adjs == adj_count-1)
				push_word(desc->strs, "and");
			else if (adjs != adj_count-1)
				push_str(desc->strs, ",");

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

	ok = find_attr(desc->parsed->attributes, desc->cell,
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

	cell_name(desc->parsed->attributes, desc->cell, &name, &name_len);

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

	ok = find_attr(desc->parsed->attributes, desc->cell, A_SHAPE, &attr);
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
	ok = push_str(desc->strs, "a(n)");
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

static int describe_group(struct describe *desc)
{
	(void)desc;
	return 0;
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
