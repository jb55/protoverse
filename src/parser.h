
#ifndef CURSOR_PARSER
#define CURSOR_PARSER

#include "cursor.h"

int consume_bytes(struct cursor *cur, const unsigned char *match, int len);
int consume_byte(struct cursor *cur, const unsigned char match);
int consume_u32(struct cursor *cur, unsigned int match);

#endif /* CURSOR_PARSER */

