
#include "cursor.h"
#include "typedefs.h"
#include <stdio.h>
#include <string.h>

void copy_cursor(struct cursor *src, struct cursor *dest)
{
	dest->start = src->start;
	dest->p = src->p;
	dest->end = src->end;
}

void make_cursor(u8 *start, u8 *end, struct cursor *cursor)
{
	cursor->start = start;
	cursor->p = start;
	cursor->end = end;
}

int cursor_index(struct cursor *cursor, int elem_size)
{
	return (cursor->p - cursor->start) / elem_size;
}


int pull_byte(struct cursor *cursor, u8 *c)
{
	if (cursor->p + 1 > cursor->end)
		return 0;

	*c = *cursor->p;
	cursor->p++;

	return 1;
}


int push_byte(struct cursor *cursor, u8 c)
{
	if (cursor->p + 1 >= cursor->end) {
		return 0;
	}

	*cursor->p = c;
	cursor->p++;

	return 1;
}


int pull_data(struct cursor *cursor, u8 *data, int len)
{
	if (cursor->p + len >= cursor->end) {
		return 0;
	}

	memcpy(data, cursor->p, len);
	cursor->p += len;

	return 1;
}

int push_data(struct cursor *cursor, u8 *data, int len)
{
	if (cursor->p + len >= cursor->end) {
		printf("push_data oob\n");
		return 0;
	}

	memcpy(cursor->p, data, len);
	cursor->p += len;

	return 1;
}

int push_int(struct cursor *cursor, int i)
{
	return push_data(cursor, (u8*)&i, sizeof(i));
}

int push_u16(struct cursor *cursor, u16 i)
{
	return push_data(cursor, (u8*)&i, sizeof(i));
}

void *index_cursor(struct cursor *cursor, u16 index, int elem_size)
{
	u8 *p;
	p = &cursor->start[elem_size * index];

	if (p > cursor->end)
		return NULL;

	return (void*)p;
}
