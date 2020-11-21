
#include "parser.h"
#include <stdio.h>


int consume_bytes(struct cursor *cursor, const unsigned char *match, int len)
{
	int i;

	if (cursor->p + len > cursor->end) {
		fprintf(stderr, "consume_bytes overflow\n");
		return 0;
	}

	for (i = 0; i < len; i++) {
		if (cursor->p[i] != match[i])
			return 0;
	}

	cursor->p += len;

	return 1;
}

int consume_byte(struct cursor *cursor, unsigned char match)
{
	return consume_bytes(cursor, &match, 1);
}

int consume_u32(struct cursor *cursor, unsigned int match)
{
	return consume_bytes(cursor, (unsigned char*)&match, sizeof(match));
}
