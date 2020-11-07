
#ifndef PROTOVERSE_DESCRIBE_H
#define PROTOVERSE_DESCRIBE_H

#include "parse.h"

struct describe {
	struct cell *cell;
	struct parser *parsed;
	struct cursor *strs;
};

int describe(struct parser *parser, u16 root_cell);
int describe_cell(struct cell *cell, struct parser *parsed, struct cursor *strbuf);
int describe_cells(struct cell *cell, struct parser *parsed, struct cursor *strs, int max_depth, int depth);

#endif
