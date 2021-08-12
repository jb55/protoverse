
#ifndef PROTOVERSE_DESCRIBE_H
#define PROTOVERSE_DESCRIBE_H

#include "parse.h"

struct describe {
	struct cell *cell;
	struct parser *parsed;
	struct cursor *strs;
};

int describe(struct parser *parser, u16 root_cell);
int describe_cell(struct describe *desc);
int describe_cells(struct describe *desc);

#endif
