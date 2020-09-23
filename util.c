
#include "util.h"

#include <memory.h>

int memeq(void *buf, int buf_len, void *buf2, int buf2_len)
{
	if (buf_len != buf2_len)
		return 0;

	return memcmp(buf, buf2, buf_len) == 0;
}
