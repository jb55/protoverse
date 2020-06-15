
#include "io.h"
#include "parse.h"

#include <assert.h>

int main(int argc, const char *argv[]) {
	static u8 file_buf[4096];
	static u8 token_buf[2048];
	struct cursor tokens;
	size_t count;
	const char *space;
	int ok;

	tokens.p = token_buf;
	tokens.end = token_buf + sizeof(token_buf);

	space = argc == 2 ? argv[1] : "satoshis-citadel.space";
	ok = read_file(space, file_buf, sizeof(file_buf), &count);
	if (!ok) {
		printf("failed to load '%s'\n", space);
		return 1;
	}


	ok = tokenize_cells(file_buf, count, &tokens);

	if (!ok) {
		printf("failed to tokenize\n");
		return 1;
	}

	assert(tokens.p == token_buf);

	ok = parse_cells(&tokens);
	if (!ok) {
		print_token_error(&tokens);
	}

	return 0;
}
