
#include "io.h"
#include "parse.h"


int main(int argc, const char *argv[]) {
	static u8 file_buf[4096];
	static u8 token_buf[2048];

	size_t count;

	const char *space = argc == 2 ? argv[1] : "satoshis-citadel.space";
	int ok = read_file(space, file_buf, sizeof(file_buf), &count);
	if (!ok) {
		printf("failed to load '%s'\n", space);
		return 1;
	}

	tokenize_space(file_buf, count, token_buf, sizeof(token_buf));

	return 0;
}
