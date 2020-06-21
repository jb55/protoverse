
#include "io.h"
#include "parse.h"

#include <assert.h>

int main(int argc, const char *argv[]) {
	static u8 file_buf[4096];
	static u8 token_buf[2048];
	static u8 attrs_buf[4096];

	struct cursor tokens;
	struct cursor attributes;

	size_t count;
	const char *space;
	int ok;

	make_cursor(attrs_buf, attrs_buf + sizeof(attrs_buf),
		    &attributes);

	make_cursor(token_buf, token_buf + sizeof(token_buf), &tokens);

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

	ok = parse_cells(&tokens, &attributes);
	if (!ok) {
		print_token_error(&tokens);
	}

	return 0;
}
